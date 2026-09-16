rule TTP_XOR_QUAD_CurrentVersionRun_bf65 {
  strings:
    $key_bf65 = { ec 0a [2] c8 04 [2] e3 28 [2] cd 0a [2] d9 11 [2] d6 0b [2] c8 16 [2] ca 17 [2] d1 11 [2] cd 16 [2] d1 39 }

  condition:
    any of them
}