rule TTP_XOR_QUAD_CurrentVersionRun_ab3d {
  strings:
    $key_ab3d = { f8 52 [2] dc 5c [2] f7 70 [2] d9 52 [2] cd 49 [2] c2 53 [2] dc 4e [2] de 4f [2] c5 49 [2] d9 4e [2] c5 61 }

  condition:
    any of them
}