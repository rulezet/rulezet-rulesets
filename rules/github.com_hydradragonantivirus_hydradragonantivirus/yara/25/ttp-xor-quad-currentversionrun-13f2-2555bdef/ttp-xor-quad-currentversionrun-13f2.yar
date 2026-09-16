rule TTP_XOR_QUAD_CurrentVersionRun_13f2 {
  strings:
    $key_13f2 = { 40 9d [2] 64 93 [2] 4f bf [2] 61 9d [2] 75 86 [2] 7a 9c [2] 64 81 [2] 66 80 [2] 7d 86 [2] 61 81 [2] 7d ae }

  condition:
    any of them
}