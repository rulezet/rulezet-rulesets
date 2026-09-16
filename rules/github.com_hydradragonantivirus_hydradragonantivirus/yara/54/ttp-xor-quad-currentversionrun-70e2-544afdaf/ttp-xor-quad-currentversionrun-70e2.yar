rule TTP_XOR_QUAD_CurrentVersionRun_70e2 {
  strings:
    $key_70e2 = { 23 8d [2] 07 83 [2] 2c af [2] 02 8d [2] 16 96 [2] 19 8c [2] 07 91 [2] 05 90 [2] 1e 96 [2] 02 91 [2] 1e be }

  condition:
    any of them
}