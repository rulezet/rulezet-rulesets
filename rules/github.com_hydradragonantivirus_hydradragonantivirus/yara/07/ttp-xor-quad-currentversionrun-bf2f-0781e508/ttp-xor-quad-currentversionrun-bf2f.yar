rule TTP_XOR_QUAD_CurrentVersionRun_bf2f {
  strings:
    $key_bf2f = { ec 40 [2] c8 4e [2] e3 62 [2] cd 40 [2] d9 5b [2] d6 41 [2] c8 5c [2] ca 5d [2] d1 5b [2] cd 5c [2] d1 73 }

  condition:
    any of them
}