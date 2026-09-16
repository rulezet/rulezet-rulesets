rule TTP_XOR_QUAD_CurrentVersionRun_c082 {
  strings:
    $key_c082 = { 93 ed [2] b7 e3 [2] 9c cf [2] b2 ed [2] a6 f6 [2] a9 ec [2] b7 f1 [2] b5 f0 [2] ae f6 [2] b2 f1 [2] ae de }

  condition:
    any of them
}