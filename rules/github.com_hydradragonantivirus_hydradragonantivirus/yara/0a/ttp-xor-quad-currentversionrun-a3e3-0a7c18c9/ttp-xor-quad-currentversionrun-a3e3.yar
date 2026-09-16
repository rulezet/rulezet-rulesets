rule TTP_XOR_QUAD_CurrentVersionRun_a3e3 {
  strings:
    $key_a3e3 = { f0 8c [2] d4 82 [2] ff ae [2] d1 8c [2] c5 97 [2] ca 8d [2] d4 90 [2] d6 91 [2] cd 97 [2] d1 90 [2] cd bf }

  condition:
    any of them
}