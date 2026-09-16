rule TTP_XOR_QUAD_CurrentVersionRun_32e0 {
  strings:
    $key_32e0 = { 61 8f [2] 45 81 [2] 6e ad [2] 40 8f [2] 54 94 [2] 5b 8e [2] 45 93 [2] 47 92 [2] 5c 94 [2] 40 93 [2] 5c bc }

  condition:
    any of them
}