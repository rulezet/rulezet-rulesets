rule TTP_XOR_MULT_DOSStub_5e74 {
  strings:
    $key_5e74 = { 0a 1c [2] 7e 04 [2] 39 06 [2] 7e 17 [2] 30 1b [2] 3c 11 [2] 2b 1a [2] 30 54 [2] 0d }

  condition:
    any of them
}