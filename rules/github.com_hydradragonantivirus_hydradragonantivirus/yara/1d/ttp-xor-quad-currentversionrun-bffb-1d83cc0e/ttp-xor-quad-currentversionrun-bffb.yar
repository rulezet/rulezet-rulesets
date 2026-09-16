rule TTP_XOR_QUAD_CurrentVersionRun_bffb {
  strings:
    $key_bffb = { ec 94 [2] c8 9a [2] e3 b6 [2] cd 94 [2] d9 8f [2] d6 95 [2] c8 88 [2] ca 89 [2] d1 8f [2] cd 88 [2] d1 a7 }

  condition:
    any of them
}