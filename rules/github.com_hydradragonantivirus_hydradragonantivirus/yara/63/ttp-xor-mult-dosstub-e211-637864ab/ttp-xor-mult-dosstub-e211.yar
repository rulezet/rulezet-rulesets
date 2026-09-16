rule TTP_XOR_MULT_DOSStub_e211 {
  strings:
    $key_e211 = { b6 79 [2] c2 61 [2] 85 63 [2] c2 72 [2] 8c 7e [2] 80 74 [2] 97 7f [2] 8c 31 [2] b1 }

  condition:
    any of them
}