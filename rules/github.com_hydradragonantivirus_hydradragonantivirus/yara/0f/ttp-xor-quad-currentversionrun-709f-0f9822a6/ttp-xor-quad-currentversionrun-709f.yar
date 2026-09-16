rule TTP_XOR_QUAD_CurrentVersionRun_709f {
  strings:
    $key_709f = { 23 f0 [2] 07 fe [2] 2c d2 [2] 02 f0 [2] 16 eb [2] 19 f1 [2] 07 ec [2] 05 ed [2] 1e eb [2] 02 ec [2] 1e c3 }

  condition:
    any of them
}