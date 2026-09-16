rule TTP_XOR_QUAD_CurrentVersionRun_ec8c {
  strings:
    $key_ec8c = { bf e3 [2] 9b ed [2] b0 c1 [2] 9e e3 [2] 8a f8 [2] 85 e2 [2] 9b ff [2] 99 fe [2] 82 f8 [2] 9e ff [2] 82 d0 }

  condition:
    any of them
}