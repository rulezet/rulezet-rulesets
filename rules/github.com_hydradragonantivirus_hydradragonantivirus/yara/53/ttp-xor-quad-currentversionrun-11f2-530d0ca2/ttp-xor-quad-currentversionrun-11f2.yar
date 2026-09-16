rule TTP_XOR_QUAD_CurrentVersionRun_11f2 {
  strings:
    $key_11f2 = { 42 9d [2] 66 93 [2] 4d bf [2] 63 9d [2] 77 86 [2] 78 9c [2] 66 81 [2] 64 80 [2] 7f 86 [2] 63 81 [2] 7f ae }

  condition:
    any of them
}