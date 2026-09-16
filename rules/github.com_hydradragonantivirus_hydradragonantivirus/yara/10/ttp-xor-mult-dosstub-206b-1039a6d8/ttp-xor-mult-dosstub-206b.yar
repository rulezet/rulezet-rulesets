rule TTP_XOR_MULT_DOSStub_206b {
  strings:
    $key_206b = { 74 03 [2] 00 1b [2] 47 19 [2] 00 08 [2] 4e 04 [2] 42 0e [2] 55 05 [2] 4e 4b [2] 73 }

  condition:
    any of them
}