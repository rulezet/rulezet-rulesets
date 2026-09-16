rule TTP_XOR_QUAD_CurrentVersionRun_bf2d {
  strings:
    $key_bf2d = { ec 42 [2] c8 4c [2] e3 60 [2] cd 42 [2] d9 59 [2] d6 43 [2] c8 5e [2] ca 5f [2] d1 59 [2] cd 5e [2] d1 71 }

  condition:
    any of them
}