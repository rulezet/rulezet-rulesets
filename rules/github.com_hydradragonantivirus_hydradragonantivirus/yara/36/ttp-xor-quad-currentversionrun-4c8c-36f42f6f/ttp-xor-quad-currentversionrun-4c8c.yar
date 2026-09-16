rule TTP_XOR_QUAD_CurrentVersionRun_4c8c {
  strings:
    $key_4c8c = { 1f e3 [2] 3b ed [2] 10 c1 [2] 3e e3 [2] 2a f8 [2] 25 e2 [2] 3b ff [2] 39 fe [2] 22 f8 [2] 3e ff [2] 22 d0 }

  condition:
    any of them
}