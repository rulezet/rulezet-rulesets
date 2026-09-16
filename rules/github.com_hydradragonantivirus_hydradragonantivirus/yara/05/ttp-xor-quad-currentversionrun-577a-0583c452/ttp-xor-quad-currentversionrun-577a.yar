rule TTP_XOR_QUAD_CurrentVersionRun_577a {
  strings:
    $key_577a = { 04 15 [2] 20 1b [2] 0b 37 [2] 25 15 [2] 31 0e [2] 3e 14 [2] 20 09 [2] 22 08 [2] 39 0e [2] 25 09 [2] 39 26 }

  condition:
    any of them
}