rule TTP_XOR_QUAD_CurrentVersionRun_74e2 {
  strings:
    $key_74e2 = { 27 8d [2] 03 83 [2] 28 af [2] 06 8d [2] 12 96 [2] 1d 8c [2] 03 91 [2] 01 90 [2] 1a 96 [2] 06 91 [2] 1a be }

  condition:
    any of them
}