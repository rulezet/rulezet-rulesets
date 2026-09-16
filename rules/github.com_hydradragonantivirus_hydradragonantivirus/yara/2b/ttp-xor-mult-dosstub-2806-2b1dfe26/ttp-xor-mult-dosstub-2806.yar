rule TTP_XOR_MULT_DOSStub_2806 {
  strings:
    $key_2806 = { 7c 6e [2] 08 76 [2] 4f 74 [2] 08 65 [2] 46 69 [2] 4a 63 [2] 5d 68 [2] 46 26 [2] 7b }

  condition:
    any of them
}