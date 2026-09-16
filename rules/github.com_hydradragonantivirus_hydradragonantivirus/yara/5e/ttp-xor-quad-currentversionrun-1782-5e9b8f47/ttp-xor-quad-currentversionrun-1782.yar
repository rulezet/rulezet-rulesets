rule TTP_XOR_QUAD_CurrentVersionRun_1782 {
  strings:
    $key_1782 = { 44 ed [2] 60 e3 [2] 4b cf [2] 65 ed [2] 71 f6 [2] 7e ec [2] 60 f1 [2] 62 f0 [2] 79 f6 [2] 65 f1 [2] 79 de }

  condition:
    any of them
}