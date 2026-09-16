rule TTP_XOR_QUAD_CurrentVersionRun_bf06 {
  strings:
    $key_bf06 = { ec 69 [2] c8 67 [2] e3 4b [2] cd 69 [2] d9 72 [2] d6 68 [2] c8 75 [2] ca 74 [2] d1 72 [2] cd 75 [2] d1 5a }

  condition:
    any of them
}