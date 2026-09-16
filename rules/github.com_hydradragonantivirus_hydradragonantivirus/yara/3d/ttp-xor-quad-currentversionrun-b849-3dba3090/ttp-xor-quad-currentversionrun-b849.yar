rule TTP_XOR_QUAD_CurrentVersionRun_b849 {
  strings:
    $key_b849 = { eb 26 [2] cf 28 [2] e4 04 [2] ca 26 [2] de 3d [2] d1 27 [2] cf 3a [2] cd 3b [2] d6 3d [2] ca 3a [2] d6 15 }

  condition:
    any of them
}