rule TTP_XOR_MULT_DOSStub_331b {
  strings:
    $key_331b = { 67 73 [2] 13 6b [2] 54 69 [2] 13 78 [2] 5d 74 [2] 51 7e [2] 46 75 [2] 5d 3b [2] 60 }

  condition:
    any of them
}