rule TTP_XOR_QUAD_CurrentVersionRun_584a {
  strings:
    $key_584a = { 0b 25 [2] 2f 2b [2] 04 07 [2] 2a 25 [2] 3e 3e [2] 31 24 [2] 2f 39 [2] 2d 38 [2] 36 3e [2] 2a 39 [2] 36 16 }

  condition:
    any of them
}