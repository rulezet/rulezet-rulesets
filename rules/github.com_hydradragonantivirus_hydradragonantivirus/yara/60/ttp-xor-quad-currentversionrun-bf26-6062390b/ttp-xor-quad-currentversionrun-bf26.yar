rule TTP_XOR_QUAD_CurrentVersionRun_bf26 {
  strings:
    $key_bf26 = { ec 49 [2] c8 47 [2] e3 6b [2] cd 49 [2] d9 52 [2] d6 48 [2] c8 55 [2] ca 54 [2] d1 52 [2] cd 55 [2] d1 7a }

  condition:
    any of them
}