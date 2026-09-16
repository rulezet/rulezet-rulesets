rule TTP_XOR_QUAD_CurrentVersionRun_f09f {
  strings:
    $key_f09f = { a3 f0 [2] 87 fe [2] ac d2 [2] 82 f0 [2] 96 eb [2] 99 f1 [2] 87 ec [2] 85 ed [2] 9e eb [2] 82 ec [2] 9e c3 }

  condition:
    any of them
}