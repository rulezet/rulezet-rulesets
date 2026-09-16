rule TTP_XOR_MULT_DOSStub_2807 {
  strings:
    $key_2807 = { 7c 6f [2] 08 77 [2] 4f 75 [2] 08 64 [2] 46 68 [2] 4a 62 [2] 5d 69 [2] 46 27 [2] 7b }

  condition:
    any of them
}