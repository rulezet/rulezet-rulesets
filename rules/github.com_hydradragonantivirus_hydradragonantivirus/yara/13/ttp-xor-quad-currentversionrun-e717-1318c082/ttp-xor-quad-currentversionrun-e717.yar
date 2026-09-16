rule TTP_XOR_QUAD_CurrentVersionRun_e717 {
  strings:
    $key_e717 = { b4 78 [2] 90 76 [2] bb 5a [2] 95 78 [2] 81 63 [2] 8e 79 [2] 90 64 [2] 92 65 [2] 89 63 [2] 95 64 [2] 89 4b }

  condition:
    any of them
}