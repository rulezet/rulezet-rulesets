rule TTP_XOR_QUAD_CurrentVersionRun_2d8c {
  strings:
    $key_2d8c = { 7e e3 [2] 5a ed [2] 71 c1 [2] 5f e3 [2] 4b f8 [2] 44 e2 [2] 5a ff [2] 58 fe [2] 43 f8 [2] 5f ff [2] 43 d0 }

  condition:
    any of them
}