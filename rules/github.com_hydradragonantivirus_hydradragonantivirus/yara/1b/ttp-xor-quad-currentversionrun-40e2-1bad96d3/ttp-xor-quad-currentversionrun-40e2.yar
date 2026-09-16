rule TTP_XOR_QUAD_CurrentVersionRun_40e2 {
  strings:
    $key_40e2 = { 13 8d [2] 37 83 [2] 1c af [2] 32 8d [2] 26 96 [2] 29 8c [2] 37 91 [2] 35 90 [2] 2e 96 [2] 32 91 [2] 2e be }

  condition:
    any of them
}