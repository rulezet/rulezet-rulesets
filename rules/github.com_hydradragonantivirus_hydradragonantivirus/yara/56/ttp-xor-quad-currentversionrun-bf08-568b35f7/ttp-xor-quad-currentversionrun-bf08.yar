rule TTP_XOR_QUAD_CurrentVersionRun_bf08 {
  strings:
    $key_bf08 = { ec 67 [2] c8 69 [2] e3 45 [2] cd 67 [2] d9 7c [2] d6 66 [2] c8 7b [2] ca 7a [2] d1 7c [2] cd 7b [2] d1 54 }

  condition:
    any of them
}