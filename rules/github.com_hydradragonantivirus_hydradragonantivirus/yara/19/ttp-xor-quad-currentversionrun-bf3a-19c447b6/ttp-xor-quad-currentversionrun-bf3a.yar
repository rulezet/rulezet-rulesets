rule TTP_XOR_QUAD_CurrentVersionRun_bf3a {
  strings:
    $key_bf3a = { ec 55 [2] c8 5b [2] e3 77 [2] cd 55 [2] d9 4e [2] d6 54 [2] c8 49 [2] ca 48 [2] d1 4e [2] cd 49 [2] d1 66 }

  condition:
    any of them
}