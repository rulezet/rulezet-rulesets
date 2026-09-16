rule TTP_XOR_QUAD_CurrentVersionRun_ef84 {
  strings:
    $key_ef84 = { bc eb [2] 98 e5 [2] b3 c9 [2] 9d eb [2] 89 f0 [2] 86 ea [2] 98 f7 [2] 9a f6 [2] 81 f0 [2] 9d f7 [2] 81 d8 }

  condition:
    any of them
}