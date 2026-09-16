rule TTP_XOR_QUAD_CurrentVersionRun_a3fe {
  strings:
    $key_a3fe = { f0 91 [2] d4 9f [2] ff b3 [2] d1 91 [2] c5 8a [2] ca 90 [2] d4 8d [2] d6 8c [2] cd 8a [2] d1 8d [2] cd a2 }

  condition:
    any of them
}