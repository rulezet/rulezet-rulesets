rule TTP_XOR_QUAD_CurrentVersionRun_0782 {
  strings:
    $key_0782 = { 54 ed [2] 70 e3 [2] 5b cf [2] 75 ed [2] 61 f6 [2] 6e ec [2] 70 f1 [2] 72 f0 [2] 69 f6 [2] 75 f1 [2] 69 de }

  condition:
    any of them
}