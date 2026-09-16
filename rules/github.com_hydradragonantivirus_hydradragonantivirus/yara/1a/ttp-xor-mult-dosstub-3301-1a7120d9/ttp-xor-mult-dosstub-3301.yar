rule TTP_XOR_MULT_DOSStub_3301 {
  strings:
    $key_3301 = { 67 69 [2] 13 71 [2] 54 73 [2] 13 62 [2] 5d 6e [2] 51 64 [2] 46 6f [2] 5d 21 [2] 60 }

  condition:
    any of them
}