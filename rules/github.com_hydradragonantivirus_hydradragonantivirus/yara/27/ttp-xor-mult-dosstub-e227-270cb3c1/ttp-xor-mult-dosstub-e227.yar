rule TTP_XOR_MULT_DOSStub_e227 {
  strings:
    $key_e227 = { b6 4f [2] c2 57 [2] 85 55 [2] c2 44 [2] 8c 48 [2] 80 42 [2] 97 49 [2] 8c 07 [2] b1 }

  condition:
    any of them
}