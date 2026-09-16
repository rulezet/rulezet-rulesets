rule TTP_XOR_QUAD_CurrentVersionRun_bf15 {
  strings:
    $key_bf15 = { ec 7a [2] c8 74 [2] e3 58 [2] cd 7a [2] d9 61 [2] d6 7b [2] c8 66 [2] ca 67 [2] d1 61 [2] cd 66 [2] d1 49 }

  condition:
    any of them
}