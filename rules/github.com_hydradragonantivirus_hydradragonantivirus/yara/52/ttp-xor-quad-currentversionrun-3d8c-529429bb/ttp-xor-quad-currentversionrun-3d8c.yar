rule TTP_XOR_QUAD_CurrentVersionRun_3d8c {
  strings:
    $key_3d8c = { 6e e3 [2] 4a ed [2] 61 c1 [2] 4f e3 [2] 5b f8 [2] 54 e2 [2] 4a ff [2] 48 fe [2] 53 f8 [2] 4f ff [2] 53 d0 }

  condition:
    any of them
}