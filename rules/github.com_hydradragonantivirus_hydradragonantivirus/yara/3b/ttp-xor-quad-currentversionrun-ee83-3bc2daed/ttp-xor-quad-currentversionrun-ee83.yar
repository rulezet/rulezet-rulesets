rule TTP_XOR_QUAD_CurrentVersionRun_ee83 {
  strings:
    $key_ee83 = { bd ec [2] 99 e2 [2] b2 ce [2] 9c ec [2] 88 f7 [2] 87 ed [2] 99 f0 [2] 9b f1 [2] 80 f7 [2] 9c f0 [2] 80 df }

  condition:
    any of them
}