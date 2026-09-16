rule TTP_XOR_QUAD_CurrentVersionRun_bf55 {
  strings:
    $key_bf55 = { ec 3a [2] c8 34 [2] e3 18 [2] cd 3a [2] d9 21 [2] d6 3b [2] c8 26 [2] ca 27 [2] d1 21 [2] cd 26 [2] d1 09 }

  condition:
    any of them
}