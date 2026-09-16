rule TTP_XOR_QUAD_CurrentVersionRun_479f {
  strings:
    $key_479f = { 14 f0 [2] 30 fe [2] 1b d2 [2] 35 f0 [2] 21 eb [2] 2e f1 [2] 30 ec [2] 32 ed [2] 29 eb [2] 35 ec [2] 29 c3 }

  condition:
    any of them
}