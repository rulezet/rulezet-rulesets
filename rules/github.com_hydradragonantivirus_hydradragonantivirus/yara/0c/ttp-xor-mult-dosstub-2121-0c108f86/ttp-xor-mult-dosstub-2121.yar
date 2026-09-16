rule TTP_XOR_MULT_DOSStub_2121 {
  strings:
    $key_2121 = { 75 49 [2] 01 51 [2] 46 53 [2] 01 42 [2] 4f 4e [2] 43 44 [2] 54 4f [2] 4f 01 [2] 72 }

  condition:
    any of them
}