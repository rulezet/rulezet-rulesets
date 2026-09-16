rule TTP_XOR_QUAD_CurrentVersionRun_f79f {
  strings:
    $key_f79f = { a4 f0 [2] 80 fe [2] ab d2 [2] 85 f0 [2] 91 eb [2] 9e f1 [2] 80 ec [2] 82 ed [2] 99 eb [2] 85 ec [2] 99 c3 }

  condition:
    any of them
}