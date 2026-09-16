rule TTP_XOR_QUAD_CurrentVersionRun_b053 {
  strings:
    $key_b053 = { e3 3c [2] c7 32 [2] ec 1e [2] c2 3c [2] d6 27 [2] d9 3d [2] c7 20 [2] c5 21 [2] de 27 [2] c2 20 [2] de 0f }

  condition:
    any of them
}