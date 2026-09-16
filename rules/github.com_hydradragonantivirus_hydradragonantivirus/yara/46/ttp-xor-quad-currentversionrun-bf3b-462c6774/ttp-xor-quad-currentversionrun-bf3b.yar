rule TTP_XOR_QUAD_CurrentVersionRun_bf3b {
  strings:
    $key_bf3b = { ec 54 [2] c8 5a [2] e3 76 [2] cd 54 [2] d9 4f [2] d6 55 [2] c8 48 [2] ca 49 [2] d1 4f [2] cd 48 [2] d1 67 }

  condition:
    any of them
}