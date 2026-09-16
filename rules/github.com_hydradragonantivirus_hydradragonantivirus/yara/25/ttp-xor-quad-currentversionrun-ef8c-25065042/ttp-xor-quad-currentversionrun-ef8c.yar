rule TTP_XOR_QUAD_CurrentVersionRun_ef8c {
  strings:
    $key_ef8c = { bc e3 [2] 98 ed [2] b3 c1 [2] 9d e3 [2] 89 f8 [2] 86 e2 [2] 98 ff [2] 9a fe [2] 81 f8 [2] 9d ff [2] 81 d0 }

  condition:
    any of them
}