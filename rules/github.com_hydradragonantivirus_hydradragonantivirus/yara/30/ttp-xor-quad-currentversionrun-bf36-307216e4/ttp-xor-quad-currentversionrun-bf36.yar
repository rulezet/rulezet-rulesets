rule TTP_XOR_QUAD_CurrentVersionRun_bf36 {
  strings:
    $key_bf36 = { ec 59 [2] c8 57 [2] e3 7b [2] cd 59 [2] d9 42 [2] d6 58 [2] c8 45 [2] ca 44 [2] d1 42 [2] cd 45 [2] d1 6a }

  condition:
    any of them
}