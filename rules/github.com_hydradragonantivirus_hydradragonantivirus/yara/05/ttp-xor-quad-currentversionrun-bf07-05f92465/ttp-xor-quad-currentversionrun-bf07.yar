rule TTP_XOR_QUAD_CurrentVersionRun_bf07 {
  strings:
    $key_bf07 = { ec 68 [2] c8 66 [2] e3 4a [2] cd 68 [2] d9 73 [2] d6 69 [2] c8 74 [2] ca 75 [2] d1 73 [2] cd 74 [2] d1 5b }

  condition:
    any of them
}