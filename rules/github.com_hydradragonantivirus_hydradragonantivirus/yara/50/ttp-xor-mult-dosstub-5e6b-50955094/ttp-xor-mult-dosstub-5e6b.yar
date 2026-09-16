rule TTP_XOR_MULT_DOSStub_5e6b {
  strings:
    $key_5e6b = { 0a 03 [2] 7e 1b [2] 39 19 [2] 7e 08 [2] 30 04 [2] 3c 0e [2] 2b 05 [2] 30 4b [2] 0d }

  condition:
    any of them
}