rule TTP_XOR_QUAD_CurrentVersionRun_054d {
  strings:
    $key_054d = { 56 22 [2] 72 2c [2] 59 00 [2] 77 22 [2] 63 39 [2] 6c 23 [2] 72 3e [2] 70 3f [2] 6b 39 [2] 77 3e [2] 6b 11 }

  condition:
    any of them
}