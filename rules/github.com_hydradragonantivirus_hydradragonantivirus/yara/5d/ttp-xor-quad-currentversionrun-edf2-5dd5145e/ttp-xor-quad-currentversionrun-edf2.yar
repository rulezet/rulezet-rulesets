rule TTP_XOR_QUAD_CurrentVersionRun_edf2 {
  strings:
    $key_edf2 = { be 9d [2] 9a 93 [2] b1 bf [2] 9f 9d [2] 8b 86 [2] 84 9c [2] 9a 81 [2] 98 80 [2] 83 86 [2] 9f 81 [2] 83 ae }

  condition:
    any of them
}