rule TTP_XOR_QUAD_CurrentVersionRun_bf21 {
  strings:
    $key_bf21 = { ec 4e [2] c8 40 [2] e3 6c [2] cd 4e [2] d9 55 [2] d6 4f [2] c8 52 [2] ca 53 [2] d1 55 [2] cd 52 [2] d1 7d }

  condition:
    any of them
}