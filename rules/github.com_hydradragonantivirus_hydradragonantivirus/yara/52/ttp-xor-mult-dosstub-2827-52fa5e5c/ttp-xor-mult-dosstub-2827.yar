rule TTP_XOR_MULT_DOSStub_2827 {
  strings:
    $key_2827 = { 7c 4f [2] 08 57 [2] 4f 55 [2] 08 44 [2] 46 48 [2] 4a 42 [2] 5d 49 [2] 46 07 [2] 7b }

  condition:
    any of them
}