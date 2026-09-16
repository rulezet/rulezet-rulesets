rule TTP_XOR_QUAD_CurrentVersionRun_30f7 {
  strings:
    $key_30f7 = { 63 98 [2] 47 96 [2] 6c ba [2] 42 98 [2] 56 83 [2] 59 99 [2] 47 84 [2] 45 85 [2] 5e 83 [2] 42 84 [2] 5e ab }

  condition:
    any of them
}