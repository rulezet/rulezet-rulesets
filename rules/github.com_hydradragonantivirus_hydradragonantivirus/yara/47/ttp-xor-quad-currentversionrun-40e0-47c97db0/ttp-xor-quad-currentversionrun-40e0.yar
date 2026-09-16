rule TTP_XOR_QUAD_CurrentVersionRun_40e0 {
  strings:
    $key_40e0 = { 13 8f [2] 37 81 [2] 1c ad [2] 32 8f [2] 26 94 [2] 29 8e [2] 37 93 [2] 35 92 [2] 2e 94 [2] 32 93 [2] 2e bc }

  condition:
    any of them
}