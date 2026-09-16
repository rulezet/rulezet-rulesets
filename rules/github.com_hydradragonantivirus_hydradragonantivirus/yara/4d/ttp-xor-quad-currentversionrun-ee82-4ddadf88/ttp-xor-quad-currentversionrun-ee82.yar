rule TTP_XOR_QUAD_CurrentVersionRun_ee82 {
  strings:
    $key_ee82 = { bd ed [2] 99 e3 [2] b2 cf [2] 9c ed [2] 88 f6 [2] 87 ec [2] 99 f1 [2] 9b f0 [2] 80 f6 [2] 9c f1 [2] 80 de }

  condition:
    any of them
}