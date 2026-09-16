rule TTP_XOR_QUAD_CurrentVersionRun_3a83 {
  strings:
    $key_3a83 = { 69 ec [2] 4d e2 [2] 66 ce [2] 48 ec [2] 5c f7 [2] 53 ed [2] 4d f0 [2] 4f f1 [2] 54 f7 [2] 48 f0 [2] 54 df }

  condition:
    any of them
}