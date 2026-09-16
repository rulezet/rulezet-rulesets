rule TTP_XOR_QUAD_CurrentVersionRun_76f2 {
  strings:
    $key_76f2 = { 25 9d [2] 01 93 [2] 2a bf [2] 04 9d [2] 10 86 [2] 1f 9c [2] 01 81 [2] 03 80 [2] 18 86 [2] 04 81 [2] 18 ae }

  condition:
    any of them
}