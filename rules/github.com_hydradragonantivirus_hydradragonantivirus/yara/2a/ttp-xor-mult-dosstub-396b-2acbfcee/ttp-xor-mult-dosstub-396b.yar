rule TTP_XOR_MULT_DOSStub_396b {
  strings:
    $key_396b = { 6d 03 [2] 19 1b [2] 5e 19 [2] 19 08 [2] 57 04 [2] 5b 0e [2] 4c 05 [2] 57 4b [2] 6a }

  condition:
    any of them
}