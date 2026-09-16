rule TTP_XOR_QUAD_CurrentVersionRun_bf39 {
  strings:
    $key_bf39 = { ec 56 [2] c8 58 [2] e3 74 [2] cd 56 [2] d9 4d [2] d6 57 [2] c8 4a [2] ca 4b [2] d1 4d [2] cd 4a [2] d1 65 }

  condition:
    any of them
}