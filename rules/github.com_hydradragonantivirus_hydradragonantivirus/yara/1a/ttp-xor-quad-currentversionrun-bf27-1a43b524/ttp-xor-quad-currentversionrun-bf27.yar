rule TTP_XOR_QUAD_CurrentVersionRun_bf27 {
  strings:
    $key_bf27 = { ec 48 [2] c8 46 [2] e3 6a [2] cd 48 [2] d9 53 [2] d6 49 [2] c8 54 [2] ca 55 [2] d1 53 [2] cd 54 [2] d1 7b }

  condition:
    any of them
}