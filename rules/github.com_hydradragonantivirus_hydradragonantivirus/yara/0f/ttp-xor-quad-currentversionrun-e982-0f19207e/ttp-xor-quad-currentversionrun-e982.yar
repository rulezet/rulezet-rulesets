rule TTP_XOR_QUAD_CurrentVersionRun_e982 {
  strings:
    $key_e982 = { ba ed [2] 9e e3 [2] b5 cf [2] 9b ed [2] 8f f6 [2] 80 ec [2] 9e f1 [2] 9c f0 [2] 87 f6 [2] 9b f1 [2] 87 de }

  condition:
    any of them
}