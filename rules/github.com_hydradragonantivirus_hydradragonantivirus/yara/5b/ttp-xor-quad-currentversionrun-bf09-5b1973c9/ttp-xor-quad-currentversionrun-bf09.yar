rule TTP_XOR_QUAD_CurrentVersionRun_bf09 {
  strings:
    $key_bf09 = { ec 66 [2] c8 68 [2] e3 44 [2] cd 66 [2] d9 7d [2] d6 67 [2] c8 7a [2] ca 7b [2] d1 7d [2] cd 7a [2] d1 55 }

  condition:
    any of them
}