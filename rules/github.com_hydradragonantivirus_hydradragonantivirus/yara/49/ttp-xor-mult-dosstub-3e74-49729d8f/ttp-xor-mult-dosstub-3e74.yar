rule TTP_XOR_MULT_DOSStub_3e74 {
  strings:
    $key_3e74 = { 6a 1c [2] 1e 04 [2] 59 06 [2] 1e 17 [2] 50 1b [2] 5c 11 [2] 4b 1a [2] 50 54 [2] 6d }

  condition:
    any of them
}