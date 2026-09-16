rule TTP_XOR_MULT_DOSStub_7cac {
  strings:
    $key_7cac = { 28 c4 [2] 5c dc [2] 1b de [2] 5c cf [2] 12 c3 [2] 1e c9 [2] 09 c2 [2] 12 8c [2] 2f }

  condition:
    any of them
}