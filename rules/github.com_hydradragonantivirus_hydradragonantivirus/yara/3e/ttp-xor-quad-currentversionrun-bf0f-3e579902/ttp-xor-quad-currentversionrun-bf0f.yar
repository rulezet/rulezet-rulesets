rule TTP_XOR_QUAD_CurrentVersionRun_bf0f {
  strings:
    $key_bf0f = { ec 60 [2] c8 6e [2] e3 42 [2] cd 60 [2] d9 7b [2] d6 61 [2] c8 7c [2] ca 7d [2] d1 7b [2] cd 7c [2] d1 53 }

  condition:
    any of them
}