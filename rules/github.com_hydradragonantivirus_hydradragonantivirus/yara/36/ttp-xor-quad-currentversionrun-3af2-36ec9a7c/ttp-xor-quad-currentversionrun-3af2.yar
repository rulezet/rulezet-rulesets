rule TTP_XOR_QUAD_CurrentVersionRun_3af2 {
  strings:
    $key_3af2 = { 69 9d [2] 4d 93 [2] 66 bf [2] 48 9d [2] 5c 86 [2] 53 9c [2] 4d 81 [2] 4f 80 [2] 54 86 [2] 48 81 [2] 54 ae }

  condition:
    any of them
}