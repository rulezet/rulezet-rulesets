rule TTP_XOR_QUAD_CurrentVersionRun_abf2 {
  strings:
    $key_abf2 = { f8 9d [2] dc 93 [2] f7 bf [2] d9 9d [2] cd 86 [2] c2 9c [2] dc 81 [2] de 80 [2] c5 86 [2] d9 81 [2] c5 ae }

  condition:
    any of them
}