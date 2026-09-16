rule TTP_XOR_QUAD_CurrentVersionRun_ed8b {
  strings:
    $key_ed8b = { be e4 [2] 9a ea [2] b1 c6 [2] 9f e4 [2] 8b ff [2] 84 e5 [2] 9a f8 [2] 98 f9 [2] 83 ff [2] 9f f8 [2] 83 d7 }

  condition:
    any of them
}