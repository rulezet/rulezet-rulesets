rule TTP_XOR_QUAD_CurrentVersionRun_f983 {
  strings:
    $key_f983 = { aa ec [2] 8e e2 [2] a5 ce [2] 8b ec [2] 9f f7 [2] 90 ed [2] 8e f0 [2] 8c f1 [2] 97 f7 [2] 8b f0 [2] 97 df }

  condition:
    any of them
}