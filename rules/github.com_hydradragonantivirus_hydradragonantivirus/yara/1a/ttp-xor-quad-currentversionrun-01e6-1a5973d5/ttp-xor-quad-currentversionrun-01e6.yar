rule TTP_XOR_QUAD_CurrentVersionRun_01e6 {
  strings:
    $key_01e6 = { 52 89 [2] 76 87 [2] 5d ab [2] 73 89 [2] 67 92 [2] 68 88 [2] 76 95 [2] 74 94 [2] 6f 92 [2] 73 95 [2] 6f ba }

  condition:
    any of them
}