rule TTP_XOR_MULT_DOSStub_4d21 {
  strings:
    $key_4d21 = { 19 49 [2] 6d 51 [2] 2a 53 [2] 6d 42 [2] 23 4e [2] 2f 44 [2] 38 4f [2] 23 01 [2] 1e }

  condition:
    any of them
}