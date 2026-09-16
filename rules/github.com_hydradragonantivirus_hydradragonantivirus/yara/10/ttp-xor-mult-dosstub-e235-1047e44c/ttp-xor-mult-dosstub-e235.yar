rule TTP_XOR_MULT_DOSStub_e235 {
  strings:
    $key_e235 = { b6 5d [2] c2 45 [2] 85 47 [2] c2 56 [2] 8c 5a [2] 80 50 [2] 97 5b [2] 8c 15 [2] b1 }

  condition:
    any of them
}