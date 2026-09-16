rule TTP_XOR_QUAD_CurrentVersionRun_50e2 {
  strings:
    $key_50e2 = { 03 8d [2] 27 83 [2] 0c af [2] 22 8d [2] 36 96 [2] 39 8c [2] 27 91 [2] 25 90 [2] 3e 96 [2] 22 91 [2] 3e be }

  condition:
    any of them
}