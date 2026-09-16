rule TTP_XOR_QUAD_CurrentVersionRun_1082 {
  strings:
    $key_1082 = { 43 ed [2] 67 e3 [2] 4c cf [2] 62 ed [2] 76 f6 [2] 79 ec [2] 67 f1 [2] 65 f0 [2] 7e f6 [2] 62 f1 [2] 7e de }

  condition:
    any of them
}