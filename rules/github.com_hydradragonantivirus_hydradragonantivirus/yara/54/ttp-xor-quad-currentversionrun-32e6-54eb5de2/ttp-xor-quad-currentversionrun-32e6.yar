rule TTP_XOR_QUAD_CurrentVersionRun_32e6 {
  strings:
    $key_32e6 = { 61 89 [2] 45 87 [2] 6e ab [2] 40 89 [2] 54 92 [2] 5b 88 [2] 45 95 [2] 47 94 [2] 5c 92 [2] 40 95 [2] 5c ba }

  condition:
    any of them
}