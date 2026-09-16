rule TTP_XOR_QUAD_CurrentVersionRun_d898 {
  strings:
    $key_d898 = { 8b f7 [2] af f9 [2] 84 d5 [2] aa f7 [2] be ec [2] b1 f6 [2] af eb [2] ad ea [2] b6 ec [2] aa eb [2] b6 c4 }

  condition:
    any of them
}