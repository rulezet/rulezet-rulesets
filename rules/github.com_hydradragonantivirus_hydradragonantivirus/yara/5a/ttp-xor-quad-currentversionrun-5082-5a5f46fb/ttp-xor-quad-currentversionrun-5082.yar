rule TTP_XOR_QUAD_CurrentVersionRun_5082 {
  strings:
    $key_5082 = { 03 ed [2] 27 e3 [2] 0c cf [2] 22 ed [2] 36 f6 [2] 39 ec [2] 27 f1 [2] 25 f0 [2] 3e f6 [2] 22 f1 [2] 3e de }

  condition:
    any of them
}