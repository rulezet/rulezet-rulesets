rule TTP_XOR_QUAD_CurrentVersionRun_bf10 {
  strings:
    $key_bf10 = { ec 7f [2] c8 71 [2] e3 5d [2] cd 7f [2] d9 64 [2] d6 7e [2] c8 63 [2] ca 62 [2] d1 64 [2] cd 63 [2] d1 4c }

  condition:
    any of them
}