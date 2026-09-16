rule TTP_XOR_QUAD_CurrentVersionRun_048c {
  strings:
    $key_048c = { 57 e3 [2] 73 ed [2] 58 c1 [2] 76 e3 [2] 62 f8 [2] 6d e2 [2] 73 ff [2] 71 fe [2] 6a f8 [2] 76 ff [2] 6a d0 }

  condition:
    any of them
}