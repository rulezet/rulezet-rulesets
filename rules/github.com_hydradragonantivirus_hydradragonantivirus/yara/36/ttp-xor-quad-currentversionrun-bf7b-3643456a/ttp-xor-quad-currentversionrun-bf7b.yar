rule TTP_XOR_QUAD_CurrentVersionRun_bf7b {
  strings:
    $key_bf7b = { ec 14 [2] c8 1a [2] e3 36 [2] cd 14 [2] d9 0f [2] d6 15 [2] c8 08 [2] ca 09 [2] d1 0f [2] cd 08 [2] d1 27 }

  condition:
    any of them
}