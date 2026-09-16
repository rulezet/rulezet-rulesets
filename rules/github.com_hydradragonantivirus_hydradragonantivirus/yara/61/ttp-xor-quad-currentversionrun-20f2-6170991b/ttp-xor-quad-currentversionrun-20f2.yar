rule TTP_XOR_QUAD_CurrentVersionRun_20f2 {
  strings:
    $key_20f2 = { 73 9d [2] 57 93 [2] 7c bf [2] 52 9d [2] 46 86 [2] 49 9c [2] 57 81 [2] 55 80 [2] 4e 86 [2] 52 81 [2] 4e ae }

  condition:
    any of them
}