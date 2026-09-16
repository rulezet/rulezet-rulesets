rule TTP_XOR_QUAD_CurrentVersionRun_7603 {
  strings:
    $key_7603 = { 25 6c [2] 01 62 [2] 2a 4e [2] 04 6c [2] 10 77 [2] 1f 6d [2] 01 70 [2] 03 71 [2] 18 77 [2] 04 70 [2] 18 5f }

  condition:
    any of them
}