rule TTP_XOR_MULT_DOSStub_406b {
  strings:
    $key_406b = { 14 03 [2] 60 1b [2] 27 19 [2] 60 08 [2] 2e 04 [2] 22 0e [2] 35 05 [2] 2e 4b [2] 13 }

  condition:
    any of them
}