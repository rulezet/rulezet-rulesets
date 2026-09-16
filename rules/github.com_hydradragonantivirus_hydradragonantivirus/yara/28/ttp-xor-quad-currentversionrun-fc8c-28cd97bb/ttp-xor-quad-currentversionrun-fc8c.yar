rule TTP_XOR_QUAD_CurrentVersionRun_fc8c {
  strings:
    $key_fc8c = { af e3 [2] 8b ed [2] a0 c1 [2] 8e e3 [2] 9a f8 [2] 95 e2 [2] 8b ff [2] 89 fe [2] 92 f8 [2] 8e ff [2] 92 d0 }

  condition:
    any of them
}