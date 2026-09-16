rule TTP_XOR_QUAD_CurrentVersionRun_bf51 {
  strings:
    $key_bf51 = { ec 3e [2] c8 30 [2] e3 1c [2] cd 3e [2] d9 25 [2] d6 3f [2] c8 22 [2] ca 23 [2] d1 25 [2] cd 22 [2] d1 0d }

  condition:
    any of them
}