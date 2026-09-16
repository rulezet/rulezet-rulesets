rule TTP_XOR_QUAD_CurrentVersionRun_33e6 {
  strings:
    $key_33e6 = { 60 89 [2] 44 87 [2] 6f ab [2] 41 89 [2] 55 92 [2] 5a 88 [2] 44 95 [2] 46 94 [2] 5d 92 [2] 41 95 [2] 5d ba }

  condition:
    any of them
}