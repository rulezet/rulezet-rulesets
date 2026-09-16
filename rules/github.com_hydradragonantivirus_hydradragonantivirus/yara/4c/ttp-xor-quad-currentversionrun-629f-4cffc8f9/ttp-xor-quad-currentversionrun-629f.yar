rule TTP_XOR_QUAD_CurrentVersionRun_629f {
  strings:
    $key_629f = { 31 f0 [2] 15 fe [2] 3e d2 [2] 10 f0 [2] 04 eb [2] 0b f1 [2] 15 ec [2] 17 ed [2] 0c eb [2] 10 ec [2] 0c c3 }

  condition:
    any of them
}