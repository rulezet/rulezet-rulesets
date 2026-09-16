rule TTP_XOR_QUAD_CurrentVersionRun_ed82 {
  strings:
    $key_ed82 = { be ed [2] 9a e3 [2] b1 cf [2] 9f ed [2] 8b f6 [2] 84 ec [2] 9a f1 [2] 98 f0 [2] 83 f6 [2] 9f f1 [2] 83 de }

  condition:
    any of them
}