rule TTP_XOR_QUAD_CurrentVersionRun_bef2 {
  strings:
    $key_bef2 = { ed 9d [2] c9 93 [2] e2 bf [2] cc 9d [2] d8 86 [2] d7 9c [2] c9 81 [2] cb 80 [2] d0 86 [2] cc 81 [2] d0 ae }

  condition:
    any of them
}