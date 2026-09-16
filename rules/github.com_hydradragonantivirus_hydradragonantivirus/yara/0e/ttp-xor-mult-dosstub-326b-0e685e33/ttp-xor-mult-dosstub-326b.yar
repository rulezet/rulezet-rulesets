rule TTP_XOR_MULT_DOSStub_326b {
  strings:
    $key_326b = { 66 03 [2] 12 1b [2] 55 19 [2] 12 08 [2] 5c 04 [2] 50 0e [2] 47 05 [2] 5c 4b [2] 61 }

  condition:
    any of them
}