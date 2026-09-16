rule TTP_XOR_QUAD_CurrentVersionRun_919f {
  strings:
    $key_919f = { c2 f0 [2] e6 fe [2] cd d2 [2] e3 f0 [2] f7 eb [2] f8 f1 [2] e6 ec [2] e4 ed [2] ff eb [2] e3 ec [2] ff c3 }

  condition:
    any of them
}