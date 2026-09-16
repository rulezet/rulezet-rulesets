rule TTP_XOR_QUAD_CurrentVersionRun_bf53 {
  strings:
    $key_bf53 = { ec 3c [2] c8 32 [2] e3 1e [2] cd 3c [2] d9 27 [2] d6 3d [2] c8 20 [2] ca 21 [2] d1 27 [2] cd 20 [2] d1 0f }

  condition:
    any of them
}