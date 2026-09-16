rule TTP_XOR_QUAD_CurrentVersionRun_5531 {
  strings:
    $key_5531 = { 06 5e [2] 22 50 [2] 09 7c [2] 27 5e [2] 33 45 [2] 3c 5f [2] 22 42 [2] 20 43 [2] 3b 45 [2] 27 42 [2] 3b 6d }

  condition:
    any of them
}