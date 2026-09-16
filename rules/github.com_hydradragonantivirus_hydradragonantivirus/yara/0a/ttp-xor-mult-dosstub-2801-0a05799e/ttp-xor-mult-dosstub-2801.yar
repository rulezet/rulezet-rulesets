rule TTP_XOR_MULT_DOSStub_2801 {
  strings:
    $key_2801 = { 7c 69 [2] 08 71 [2] 4f 73 [2] 08 62 [2] 46 6e [2] 4a 64 [2] 5d 6f [2] 46 21 [2] 7b }

  condition:
    any of them
}