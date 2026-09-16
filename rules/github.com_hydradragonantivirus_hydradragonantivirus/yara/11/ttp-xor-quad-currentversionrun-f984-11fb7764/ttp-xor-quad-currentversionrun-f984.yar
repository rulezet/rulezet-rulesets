rule TTP_XOR_QUAD_CurrentVersionRun_f984 {
  strings:
    $key_f984 = { aa eb [2] 8e e5 [2] a5 c9 [2] 8b eb [2] 9f f0 [2] 90 ea [2] 8e f7 [2] 8c f6 [2] 97 f0 [2] 8b f7 [2] 97 d8 }

  condition:
    any of them
}