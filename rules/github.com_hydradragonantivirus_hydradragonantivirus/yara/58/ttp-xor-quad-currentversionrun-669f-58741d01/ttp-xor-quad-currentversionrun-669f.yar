rule TTP_XOR_QUAD_CurrentVersionRun_669f {
  strings:
    $key_669f = { 35 f0 [2] 11 fe [2] 3a d2 [2] 14 f0 [2] 00 eb [2] 0f f1 [2] 11 ec [2] 13 ed [2] 08 eb [2] 14 ec [2] 08 c3 }

  condition:
    any of them
}