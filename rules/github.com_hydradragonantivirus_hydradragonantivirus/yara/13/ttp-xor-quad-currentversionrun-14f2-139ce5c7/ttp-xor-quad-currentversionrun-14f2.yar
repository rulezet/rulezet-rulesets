rule TTP_XOR_QUAD_CurrentVersionRun_14f2 {
  strings:
    $key_14f2 = { 47 9d [2] 63 93 [2] 48 bf [2] 66 9d [2] 72 86 [2] 7d 9c [2] 63 81 [2] 61 80 [2] 7a 86 [2] 66 81 [2] 7a ae }

  condition:
    any of them
}