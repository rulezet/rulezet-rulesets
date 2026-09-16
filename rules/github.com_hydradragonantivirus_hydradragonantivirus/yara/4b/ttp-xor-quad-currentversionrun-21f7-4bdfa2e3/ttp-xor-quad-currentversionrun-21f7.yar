rule TTP_XOR_QUAD_CurrentVersionRun_21f7 {
  strings:
    $key_21f7 = { 72 98 [2] 56 96 [2] 7d ba [2] 53 98 [2] 47 83 [2] 48 99 [2] 56 84 [2] 54 85 [2] 4f 83 [2] 53 84 [2] 4f ab }

  condition:
    any of them
}