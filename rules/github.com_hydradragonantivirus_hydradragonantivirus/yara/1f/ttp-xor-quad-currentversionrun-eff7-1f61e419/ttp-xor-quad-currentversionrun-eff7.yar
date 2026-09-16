rule TTP_XOR_QUAD_CurrentVersionRun_eff7 {
  strings:
    $key_eff7 = { bc 98 [2] 98 96 [2] b3 ba [2] 9d 98 [2] 89 83 [2] 86 99 [2] 98 84 [2] 9a 85 [2] 81 83 [2] 9d 84 [2] 81 ab }

  condition:
    any of them
}