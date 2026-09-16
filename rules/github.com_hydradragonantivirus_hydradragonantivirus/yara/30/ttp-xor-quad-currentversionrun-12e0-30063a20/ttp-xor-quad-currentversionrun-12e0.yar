rule TTP_XOR_QUAD_CurrentVersionRun_12e0 {
  strings:
    $key_12e0 = { 41 8f [2] 65 81 [2] 4e ad [2] 60 8f [2] 74 94 [2] 7b 8e [2] 65 93 [2] 67 92 [2] 7c 94 [2] 60 93 [2] 7c bc }

  condition:
    any of them
}