rule TTP_XOR_QUAD_CurrentVersionRun_bf01 {
  strings:
    $key_bf01 = { ec 6e [2] c8 60 [2] e3 4c [2] cd 6e [2] d9 75 [2] d6 6f [2] c8 72 [2] ca 73 [2] d1 75 [2] cd 72 [2] d1 5d }

  condition:
    any of them
}