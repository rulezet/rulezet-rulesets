rule TTP_XOR_QUAD_CurrentVersionRun_729f {
  strings:
    $key_729f = { 21 f0 [2] 05 fe [2] 2e d2 [2] 00 f0 [2] 14 eb [2] 1b f1 [2] 05 ec [2] 07 ed [2] 1c eb [2] 00 ec [2] 1c c3 }

  condition:
    any of them
}