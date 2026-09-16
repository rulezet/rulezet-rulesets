rule TTP_XOR_QUAD_CurrentVersionRun_0c8c {
  strings:
    $key_0c8c = { 5f e3 [2] 7b ed [2] 50 c1 [2] 7e e3 [2] 6a f8 [2] 65 e2 [2] 7b ff [2] 79 fe [2] 62 f8 [2] 7e ff [2] 62 d0 }

  condition:
    any of them
}