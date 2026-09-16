rule TTP_XOR_MULT_DOSStub_e278 {
  strings:
    $key_e278 = { b6 10 [2] c2 08 [2] 85 0a [2] c2 1b [2] 8c 17 [2] 80 1d [2] 97 16 [2] 8c 58 [2] b1 }

  condition:
    any of them
}