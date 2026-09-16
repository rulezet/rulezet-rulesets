rule TTP_XOR_QUAD_CurrentVersionRun_3747 {
  strings:
    $key_3747 = { 64 28 [2] 40 26 [2] 6b 0a [2] 45 28 [2] 51 33 [2] 5e 29 [2] 40 34 [2] 42 35 [2] 59 33 [2] 45 34 [2] 59 1b }

  condition:
    any of them
}