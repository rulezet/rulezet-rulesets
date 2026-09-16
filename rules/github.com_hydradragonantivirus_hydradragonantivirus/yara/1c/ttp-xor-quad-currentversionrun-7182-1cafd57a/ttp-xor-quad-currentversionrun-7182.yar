rule TTP_XOR_QUAD_CurrentVersionRun_7182 {
  strings:
    $key_7182 = { 22 ed [2] 06 e3 [2] 2d cf [2] 03 ed [2] 17 f6 [2] 18 ec [2] 06 f1 [2] 04 f0 [2] 1f f6 [2] 03 f1 [2] 1f de }

  condition:
    any of them
}