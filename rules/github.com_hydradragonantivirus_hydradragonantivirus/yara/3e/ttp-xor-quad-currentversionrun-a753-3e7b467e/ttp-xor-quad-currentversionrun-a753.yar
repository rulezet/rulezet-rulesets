rule TTP_XOR_QUAD_CurrentVersionRun_a753 {
  strings:
    $key_a753 = { f4 3c [2] d0 32 [2] fb 1e [2] d5 3c [2] c1 27 [2] ce 3d [2] d0 20 [2] d2 21 [2] c9 27 [2] d5 20 [2] c9 0f }

  condition:
    any of them
}