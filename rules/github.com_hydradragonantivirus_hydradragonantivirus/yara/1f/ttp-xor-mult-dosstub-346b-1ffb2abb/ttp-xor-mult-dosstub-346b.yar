rule TTP_XOR_MULT_DOSStub_346b {
  strings:
    $key_346b = { 60 03 [2] 14 1b [2] 53 19 [2] 14 08 [2] 5a 04 [2] 56 0e [2] 41 05 [2] 5a 4b [2] 67 }

  condition:
    any of them
}