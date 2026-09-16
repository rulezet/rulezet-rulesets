rule TTP_XOR_QUAD_CurrentVersionRun_ff8c {
  strings:
    $key_ff8c = { ac e3 [2] 88 ed [2] a3 c1 [2] 8d e3 [2] 99 f8 [2] 96 e2 [2] 88 ff [2] 8a fe [2] 91 f8 [2] 8d ff [2] 91 d0 }

  condition:
    any of them
}