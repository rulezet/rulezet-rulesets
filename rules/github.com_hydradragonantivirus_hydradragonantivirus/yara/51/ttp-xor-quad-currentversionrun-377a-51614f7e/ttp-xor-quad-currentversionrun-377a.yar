rule TTP_XOR_QUAD_CurrentVersionRun_377a {
  strings:
    $key_377a = { 64 15 [2] 40 1b [2] 6b 37 [2] 45 15 [2] 51 0e [2] 5e 14 [2] 40 09 [2] 42 08 [2] 59 0e [2] 45 09 [2] 59 26 }

  condition:
    any of them
}