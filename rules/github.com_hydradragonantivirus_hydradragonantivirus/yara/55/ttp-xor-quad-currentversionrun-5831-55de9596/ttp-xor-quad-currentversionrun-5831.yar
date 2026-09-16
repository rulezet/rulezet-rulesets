rule TTP_XOR_QUAD_CurrentVersionRun_5831 {
  strings:
    $key_5831 = { 0b 5e [2] 2f 50 [2] 04 7c [2] 2a 5e [2] 3e 45 [2] 31 5f [2] 2f 42 [2] 2d 43 [2] 36 45 [2] 2a 42 [2] 36 6d }

  condition:
    any of them
}