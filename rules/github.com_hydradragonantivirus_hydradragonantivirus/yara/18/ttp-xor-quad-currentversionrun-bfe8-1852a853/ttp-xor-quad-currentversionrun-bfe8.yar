rule TTP_XOR_QUAD_CurrentVersionRun_bfe8 {
  strings:
    $key_bfe8 = { ec 87 [2] c8 89 [2] e3 a5 [2] cd 87 [2] d9 9c [2] d6 86 [2] c8 9b [2] ca 9a [2] d1 9c [2] cd 9b [2] d1 b4 }

  condition:
    any of them
}