rule TTP_XOR_QUAD_CurrentVersionRun_ba9f {
  strings:
    $key_ba9f = { e9 f0 [2] cd fe [2] e6 d2 [2] c8 f0 [2] dc eb [2] d3 f1 [2] cd ec [2] cf ed [2] d4 eb [2] c8 ec [2] d4 c3 }

  condition:
    any of them
}