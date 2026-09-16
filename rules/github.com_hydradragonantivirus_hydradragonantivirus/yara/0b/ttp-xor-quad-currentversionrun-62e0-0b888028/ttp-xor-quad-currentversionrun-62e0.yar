rule TTP_XOR_QUAD_CurrentVersionRun_62e0 {
  strings:
    $key_62e0 = { 31 8f [2] 15 81 [2] 3e ad [2] 10 8f [2] 04 94 [2] 0b 8e [2] 15 93 [2] 17 92 [2] 0c 94 [2] 10 93 [2] 0c bc }

  condition:
    any of them
}