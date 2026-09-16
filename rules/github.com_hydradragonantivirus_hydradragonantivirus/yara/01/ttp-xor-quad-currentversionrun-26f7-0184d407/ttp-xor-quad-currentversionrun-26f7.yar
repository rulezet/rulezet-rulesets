rule TTP_XOR_QUAD_CurrentVersionRun_26f7 {
  strings:
    $key_26f7 = { 75 98 [2] 51 96 [2] 7a ba [2] 54 98 [2] 40 83 [2] 4f 99 [2] 51 84 [2] 53 85 [2] 48 83 [2] 54 84 [2] 48 ab }

  condition:
    any of them
}