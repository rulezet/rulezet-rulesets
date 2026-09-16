rule TTP_XOR_QUAD_CurrentVersionRun_bfef {
  strings:
    $key_bfef = { ec 80 [2] c8 8e [2] e3 a2 [2] cd 80 [2] d9 9b [2] d6 81 [2] c8 9c [2] ca 9d [2] d1 9b [2] cd 9c [2] d1 b3 }

  condition:
    any of them
}