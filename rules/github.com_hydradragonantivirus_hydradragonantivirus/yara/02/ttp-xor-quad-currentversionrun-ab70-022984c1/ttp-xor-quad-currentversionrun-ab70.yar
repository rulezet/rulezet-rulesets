rule TTP_XOR_QUAD_CurrentVersionRun_ab70 {
  strings:
    $key_ab70 = { f8 1f [2] dc 11 [2] f7 3d [2] d9 1f [2] cd 04 [2] c2 1e [2] dc 03 [2] de 02 [2] c5 04 [2] d9 03 [2] c5 2c }

  condition:
    any of them
}