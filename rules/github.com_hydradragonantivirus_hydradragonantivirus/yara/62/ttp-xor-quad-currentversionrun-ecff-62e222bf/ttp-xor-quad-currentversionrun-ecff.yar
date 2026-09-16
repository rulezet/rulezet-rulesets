rule TTP_XOR_QUAD_CurrentVersionRun_ecff {
  strings:
    $key_ecff = { bf 90 [2] 9b 9e [2] b0 b2 [2] 9e 90 [2] 8a 8b [2] 85 91 [2] 9b 8c [2] 99 8d [2] 82 8b [2] 9e 8c [2] 82 a3 }

  condition:
    any of them
}