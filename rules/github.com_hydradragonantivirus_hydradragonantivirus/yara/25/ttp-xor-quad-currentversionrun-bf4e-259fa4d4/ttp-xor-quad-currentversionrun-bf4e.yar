rule TTP_XOR_QUAD_CurrentVersionRun_bf4e {
  strings:
    $key_bf4e = { ec 21 [2] c8 2f [2] e3 03 [2] cd 21 [2] d9 3a [2] d6 20 [2] c8 3d [2] ca 3c [2] d1 3a [2] cd 3d [2] d1 12 }

  condition:
    any of them
}