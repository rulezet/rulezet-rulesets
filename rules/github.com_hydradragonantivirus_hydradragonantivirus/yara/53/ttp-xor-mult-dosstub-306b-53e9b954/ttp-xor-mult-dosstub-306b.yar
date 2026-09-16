rule TTP_XOR_MULT_DOSStub_306b {
  strings:
    $key_306b = { 64 03 [2] 10 1b [2] 57 19 [2] 10 08 [2] 5e 04 [2] 52 0e [2] 45 05 [2] 5e 4b [2] 63 }

  condition:
    any of them
}