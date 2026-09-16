rule TTP_XOR_QUAD_CurrentVersionRun_bf52 {
  strings:
    $key_bf52 = { ec 3d [2] c8 33 [2] e3 1f [2] cd 3d [2] d9 26 [2] d6 3c [2] c8 21 [2] ca 20 [2] d1 26 [2] cd 21 [2] d1 0e }

  condition:
    any of them
}