rule TTP_XOR_QUAD_CurrentVersionRun_bff0 {
  strings:
    $key_bff0 = { ec 9f [2] c8 91 [2] e3 bd [2] cd 9f [2] d9 84 [2] d6 9e [2] c8 83 [2] ca 82 [2] d1 84 [2] cd 83 [2] d1 ac }

  condition:
    any of them
}