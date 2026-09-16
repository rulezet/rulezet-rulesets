rule TTP_XOR_QUAD_CurrentVersionRun_a38e {
  strings:
    $key_a38e = { f0 e1 [2] d4 ef [2] ff c3 [2] d1 e1 [2] c5 fa [2] ca e0 [2] d4 fd [2] d6 fc [2] cd fa [2] d1 fd [2] cd d2 }

  condition:
    any of them
}