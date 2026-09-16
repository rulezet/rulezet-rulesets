rule TTP_XOR_QUAD_CurrentVersionRun_c89f {
  strings:
    $key_c89f = { 9b f0 [2] bf fe [2] 94 d2 [2] ba f0 [2] ae eb [2] a1 f1 [2] bf ec [2] bd ed [2] a6 eb [2] ba ec [2] a6 c3 }

  condition:
    any of them
}