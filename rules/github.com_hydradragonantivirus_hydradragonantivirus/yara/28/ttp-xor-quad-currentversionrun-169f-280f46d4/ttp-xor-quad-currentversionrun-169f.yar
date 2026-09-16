rule TTP_XOR_QUAD_CurrentVersionRun_169f {
  strings:
    $key_169f = { 45 f0 [2] 61 fe [2] 4a d2 [2] 64 f0 [2] 70 eb [2] 7f f1 [2] 61 ec [2] 63 ed [2] 78 eb [2] 64 ec [2] 78 c3 }

  condition:
    any of them
}