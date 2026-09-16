rule TTP_XOR_QUAD_CurrentVersionRun_a49f {
  strings:
    $key_a49f = { f7 f0 [2] d3 fe [2] f8 d2 [2] d6 f0 [2] c2 eb [2] cd f1 [2] d3 ec [2] d1 ed [2] ca eb [2] d6 ec [2] ca c3 }

  condition:
    any of them
}