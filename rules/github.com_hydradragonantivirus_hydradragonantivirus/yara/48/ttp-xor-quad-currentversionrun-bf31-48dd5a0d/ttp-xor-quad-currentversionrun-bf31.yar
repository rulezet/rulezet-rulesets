rule TTP_XOR_QUAD_CurrentVersionRun_bf31 {
  strings:
    $key_bf31 = { ec 5e [2] c8 50 [2] e3 7c [2] cd 5e [2] d9 45 [2] d6 5f [2] c8 42 [2] ca 43 [2] d1 45 [2] cd 42 [2] d1 6d }

  condition:
    any of them
}