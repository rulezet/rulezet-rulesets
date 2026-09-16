rule TTP_XOR_QUAD_CurrentVersionRun_209f {
  strings:
    $key_209f = { 73 f0 [2] 57 fe [2] 7c d2 [2] 52 f0 [2] 46 eb [2] 49 f1 [2] 57 ec [2] 55 ed [2] 4e eb [2] 52 ec [2] 4e c3 }

  condition:
    any of them
}