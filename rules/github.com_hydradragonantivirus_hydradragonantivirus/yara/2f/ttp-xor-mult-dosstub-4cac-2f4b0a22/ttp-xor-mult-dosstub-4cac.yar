rule TTP_XOR_MULT_DOSStub_4cac {
  strings:
    $key_4cac = { 18 c4 [2] 6c dc [2] 2b de [2] 6c cf [2] 22 c3 [2] 2e c9 [2] 39 c2 [2] 22 8c [2] 1f }

  condition:
    any of them
}