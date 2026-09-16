rule TTP_XOR_QUAD_CurrentVersionRun_02e0 {
  strings:
    $key_02e0 = { 51 8f [2] 75 81 [2] 5e ad [2] 70 8f [2] 64 94 [2] 6b 8e [2] 75 93 [2] 77 92 [2] 6c 94 [2] 70 93 [2] 6c bc }

  condition:
    any of them
}