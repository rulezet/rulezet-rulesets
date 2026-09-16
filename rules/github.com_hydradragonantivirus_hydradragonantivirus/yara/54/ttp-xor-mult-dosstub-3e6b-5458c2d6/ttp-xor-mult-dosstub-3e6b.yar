rule TTP_XOR_MULT_DOSStub_3e6b {
  strings:
    $key_3e6b = { 6a 03 [2] 1e 1b [2] 59 19 [2] 1e 08 [2] 50 04 [2] 5c 0e [2] 4b 05 [2] 50 4b [2] 6d }

  condition:
    any of them
}