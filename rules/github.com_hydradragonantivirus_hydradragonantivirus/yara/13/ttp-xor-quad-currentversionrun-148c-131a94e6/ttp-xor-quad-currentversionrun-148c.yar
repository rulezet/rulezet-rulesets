rule TTP_XOR_QUAD_CurrentVersionRun_148c {
  strings:
    $key_148c = { 47 e3 [2] 63 ed [2] 48 c1 [2] 66 e3 [2] 72 f8 [2] 7d e2 [2] 63 ff [2] 61 fe [2] 7a f8 [2] 66 ff [2] 7a d0 }

  condition:
    any of them
}