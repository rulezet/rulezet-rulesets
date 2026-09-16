rule TTP_XOR_QUAD_CurrentVersionRun_26f2 {
  strings:
    $key_26f2 = { 75 9d [2] 51 93 [2] 7a bf [2] 54 9d [2] 40 86 [2] 4f 9c [2] 51 81 [2] 53 80 [2] 48 86 [2] 54 81 [2] 48 ae }

  condition:
    any of them
}