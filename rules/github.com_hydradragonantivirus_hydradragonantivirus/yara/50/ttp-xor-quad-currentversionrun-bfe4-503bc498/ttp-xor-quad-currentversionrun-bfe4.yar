rule TTP_XOR_QUAD_CurrentVersionRun_bfe4 {
  strings:
    $key_bfe4 = { ec 8b [2] c8 85 [2] e3 a9 [2] cd 8b [2] d9 90 [2] d6 8a [2] c8 97 [2] ca 96 [2] d1 90 [2] cd 97 [2] d1 b8 }

  condition:
    any of them
}