rule TTP_XOR_QUAD_CurrentVersionRun_bf70 {
  strings:
    $key_bf70 = { ec 1f [2] c8 11 [2] e3 3d [2] cd 1f [2] d9 04 [2] d6 1e [2] c8 03 [2] ca 02 [2] d1 04 [2] cd 03 [2] d1 2c }

  condition:
    any of them
}