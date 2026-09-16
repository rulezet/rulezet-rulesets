rule TTP_XOR_QUAD_CurrentVersionRun_6531 {
  strings:
    $key_6531 = { 36 5e [2] 12 50 [2] 39 7c [2] 17 5e [2] 03 45 [2] 0c 5f [2] 12 42 [2] 10 43 [2] 0b 45 [2] 17 42 [2] 0b 6d }

  condition:
    any of them
}