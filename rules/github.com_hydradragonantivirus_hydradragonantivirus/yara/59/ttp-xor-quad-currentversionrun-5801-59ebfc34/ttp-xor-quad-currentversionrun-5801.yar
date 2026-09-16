rule TTP_XOR_QUAD_CurrentVersionRun_5801 {
  strings:
    $key_5801 = { 0b 6e [2] 2f 60 [2] 04 4c [2] 2a 6e [2] 3e 75 [2] 31 6f [2] 2f 72 [2] 2d 73 [2] 36 75 [2] 2a 72 [2] 36 5d }

  condition:
    any of them
}