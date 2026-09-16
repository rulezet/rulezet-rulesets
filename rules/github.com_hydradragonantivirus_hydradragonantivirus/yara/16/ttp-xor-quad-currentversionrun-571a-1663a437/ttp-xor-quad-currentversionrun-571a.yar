rule TTP_XOR_QUAD_CurrentVersionRun_571a {
  strings:
    $key_571a = { 04 75 [2] 20 7b [2] 0b 57 [2] 25 75 [2] 31 6e [2] 3e 74 [2] 20 69 [2] 22 68 [2] 39 6e [2] 25 69 [2] 39 46 }

  condition:
    any of them
}