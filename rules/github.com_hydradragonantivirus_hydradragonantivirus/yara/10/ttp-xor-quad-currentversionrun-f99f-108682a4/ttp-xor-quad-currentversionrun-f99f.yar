rule TTP_XOR_QUAD_CurrentVersionRun_f99f {
  strings:
    $key_f99f = { aa f0 [2] 8e fe [2] a5 d2 [2] 8b f0 [2] 9f eb [2] 90 f1 [2] 8e ec [2] 8c ed [2] 97 eb [2] 8b ec [2] 97 c3 }

  condition:
    any of them
}