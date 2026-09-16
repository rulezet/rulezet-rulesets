rule TTP_XOR_QUAD_CurrentVersionRun_1d8c {
  strings:
    $key_1d8c = { 4e e3 [2] 6a ed [2] 41 c1 [2] 6f e3 [2] 7b f8 [2] 74 e2 [2] 6a ff [2] 68 fe [2] 73 f8 [2] 6f ff [2] 73 d0 }

  condition:
    any of them
}