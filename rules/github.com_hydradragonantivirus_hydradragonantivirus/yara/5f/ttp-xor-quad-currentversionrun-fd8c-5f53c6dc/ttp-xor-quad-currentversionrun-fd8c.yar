rule TTP_XOR_QUAD_CurrentVersionRun_fd8c {
  strings:
    $key_fd8c = { ae e3 [2] 8a ed [2] a1 c1 [2] 8f e3 [2] 9b f8 [2] 94 e2 [2] 8a ff [2] 88 fe [2] 93 f8 [2] 8f ff [2] 93 d0 }

  condition:
    any of them
}