rule TTP_XOR_QUAD_CurrentVersionRun_bf1f {
  strings:
    $key_bf1f = { ec 70 [2] c8 7e [2] e3 52 [2] cd 70 [2] d9 6b [2] d6 71 [2] c8 6c [2] ca 6d [2] d1 6b [2] cd 6c [2] d1 43 }

  condition:
    any of them
}