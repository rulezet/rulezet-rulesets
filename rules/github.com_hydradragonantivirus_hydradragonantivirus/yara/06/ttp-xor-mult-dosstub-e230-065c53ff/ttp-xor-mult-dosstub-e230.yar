rule TTP_XOR_MULT_DOSStub_e230 {
  strings:
    $key_e230 = { b6 58 [2] c2 40 [2] 85 42 [2] c2 53 [2] 8c 5f [2] 80 55 [2] 97 5e [2] 8c 10 [2] b1 }

  condition:
    any of them
}