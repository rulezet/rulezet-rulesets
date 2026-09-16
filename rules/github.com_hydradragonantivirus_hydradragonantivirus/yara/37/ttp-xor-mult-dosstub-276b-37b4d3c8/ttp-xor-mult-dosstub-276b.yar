rule TTP_XOR_MULT_DOSStub_276b {
  strings:
    $key_276b = { 73 03 [2] 07 1b [2] 40 19 [2] 07 08 [2] 49 04 [2] 45 0e [2] 52 05 [2] 49 4b [2] 74 }

  condition:
    any of them
}