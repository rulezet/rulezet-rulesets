rule TTP_XOR_QUAD_CurrentVersionRun_02f0 {
  strings:
    $key_02f0 = { 51 9f [2] 75 91 [2] 5e bd [2] 70 9f [2] 64 84 [2] 6b 9e [2] 75 83 [2] 77 82 [2] 6c 84 [2] 70 83 [2] 6c ac }

  condition:
    any of them
}