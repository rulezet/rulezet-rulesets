rule TTP_XOR_QUAD_CurrentVersionRun_a30f {
  strings:
    $key_a30f = { f0 60 [2] d4 6e [2] ff 42 [2] d1 60 [2] c5 7b [2] ca 61 [2] d4 7c [2] d6 7d [2] cd 7b [2] d1 7c [2] cd 53 }

  condition:
    any of them
}