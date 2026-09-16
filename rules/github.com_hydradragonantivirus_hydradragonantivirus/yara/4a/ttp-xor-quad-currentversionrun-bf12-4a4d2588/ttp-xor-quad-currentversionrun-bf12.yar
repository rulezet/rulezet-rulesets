rule TTP_XOR_QUAD_CurrentVersionRun_bf12 {
  strings:
    $key_bf12 = { ec 7d [2] c8 73 [2] e3 5f [2] cd 7d [2] d9 66 [2] d6 7c [2] c8 61 [2] ca 60 [2] d1 66 [2] cd 61 [2] d1 4e }

  condition:
    any of them
}