rule TTP_XOR_QUAD_CurrentVersionRun_b752 {
  strings:
    $key_b752 = { e4 3d [2] c0 33 [2] eb 1f [2] c5 3d [2] d1 26 [2] de 3c [2] c0 21 [2] c2 20 [2] d9 26 [2] c5 21 [2] d9 0e }

  condition:
    any of them
}