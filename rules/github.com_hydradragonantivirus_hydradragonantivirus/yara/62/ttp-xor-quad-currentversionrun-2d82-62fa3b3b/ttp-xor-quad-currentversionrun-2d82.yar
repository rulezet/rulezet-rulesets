rule TTP_XOR_QUAD_CurrentVersionRun_2d82 {
  strings:
    $key_2d82 = { 7e ed [2] 5a e3 [2] 71 cf [2] 5f ed [2] 4b f6 [2] 44 ec [2] 5a f1 [2] 58 f0 [2] 43 f6 [2] 5f f1 [2] 43 de }

  condition:
    any of them
}