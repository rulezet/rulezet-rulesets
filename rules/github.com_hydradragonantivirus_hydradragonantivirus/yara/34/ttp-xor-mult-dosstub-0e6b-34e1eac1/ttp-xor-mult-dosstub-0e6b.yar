rule TTP_XOR_MULT_DOSStub_0e6b {
  strings:
    $key_0e6b = { 5a 03 [2] 2e 1b [2] 69 19 [2] 2e 08 [2] 60 04 [2] 6c 0e [2] 7b 05 [2] 60 4b [2] 5d }

  condition:
    any of them
}