rule TTP_XOR_QUAD_CurrentVersionRun_279f {
  strings:
    $key_279f = { 74 f0 [2] 50 fe [2] 7b d2 [2] 55 f0 [2] 41 eb [2] 4e f1 [2] 50 ec [2] 52 ed [2] 49 eb [2] 55 ec [2] 49 c3 }

  condition:
    any of them
}