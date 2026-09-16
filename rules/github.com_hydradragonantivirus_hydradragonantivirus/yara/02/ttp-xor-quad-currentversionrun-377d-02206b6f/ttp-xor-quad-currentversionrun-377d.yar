rule TTP_XOR_QUAD_CurrentVersionRun_377d {
  strings:
    $key_377d = { 64 12 [2] 40 1c [2] 6b 30 [2] 45 12 [2] 51 09 [2] 5e 13 [2] 40 0e [2] 42 0f [2] 59 09 [2] 45 0e [2] 59 21 }

  condition:
    any of them
}