rule TTP_XOR_QUAD_CurrentVersionRun_ed83 {
  strings:
    $key_ed83 = { be ec [2] 9a e2 [2] b1 ce [2] 9f ec [2] 8b f7 [2] 84 ed [2] 9a f0 [2] 98 f1 [2] 83 f7 [2] 9f f0 [2] 83 df }

  condition:
    any of them
}