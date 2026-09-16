rule TTP_XOR_QUAD_CurrentVersionRun_f683 {
  strings:
    $key_f683 = { a5 ec [2] 81 e2 [2] aa ce [2] 84 ec [2] 90 f7 [2] 9f ed [2] 81 f0 [2] 83 f1 [2] 98 f7 [2] 84 f0 [2] 98 df }

  condition:
    any of them
}