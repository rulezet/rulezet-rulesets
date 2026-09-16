rule TTP_XOR_QUAD_CurrentVersionRun_72e0 {
  strings:
    $key_72e0 = { 21 8f [2] 05 81 [2] 2e ad [2] 00 8f [2] 14 94 [2] 1b 8e [2] 05 93 [2] 07 92 [2] 1c 94 [2] 00 93 [2] 1c bc }

  condition:
    any of them
}