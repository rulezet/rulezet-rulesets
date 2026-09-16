rule TTP_XOR_QUAD_CurrentVersionRun_7082 {
  strings:
    $key_7082 = { 23 ed [2] 07 e3 [2] 2c cf [2] 02 ed [2] 16 f6 [2] 19 ec [2] 07 f1 [2] 05 f0 [2] 1e f6 [2] 02 f1 [2] 1e de }

  condition:
    any of them
}