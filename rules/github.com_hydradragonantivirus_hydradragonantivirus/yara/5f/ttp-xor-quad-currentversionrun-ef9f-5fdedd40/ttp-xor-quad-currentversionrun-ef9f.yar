rule TTP_XOR_QUAD_CurrentVersionRun_ef9f {
  strings:
    $key_ef9f = { bc f0 [2] 98 fe [2] b3 d2 [2] 9d f0 [2] 89 eb [2] 86 f1 [2] 98 ec [2] 9a ed [2] 81 eb [2] 9d ec [2] 81 c3 }

  condition:
    any of them
}