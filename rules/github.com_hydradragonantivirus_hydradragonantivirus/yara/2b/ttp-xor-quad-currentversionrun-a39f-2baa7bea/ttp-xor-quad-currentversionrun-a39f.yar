rule TTP_XOR_QUAD_CurrentVersionRun_a39f {
  strings:
    $key_a39f = { f0 f0 [2] d4 fe [2] ff d2 [2] d1 f0 [2] c5 eb [2] ca f1 [2] d4 ec [2] d6 ed [2] cd eb [2] d1 ec [2] cd c3 }

  condition:
    any of them
}