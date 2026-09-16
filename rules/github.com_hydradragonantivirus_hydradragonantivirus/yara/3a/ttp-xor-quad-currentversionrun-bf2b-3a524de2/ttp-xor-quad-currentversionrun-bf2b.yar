rule TTP_XOR_QUAD_CurrentVersionRun_bf2b {
  strings:
    $key_bf2b = { ec 44 [2] c8 4a [2] e3 66 [2] cd 44 [2] d9 5f [2] d6 45 [2] c8 58 [2] ca 59 [2] d1 5f [2] cd 58 [2] d1 77 }

  condition:
    any of them
}