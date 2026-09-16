rule TTP_XOR_QUAD_CurrentVersionRun_627a {
  strings:
    $key_627a = { 31 15 [2] 15 1b [2] 3e 37 [2] 10 15 [2] 04 0e [2] 0b 14 [2] 15 09 [2] 17 08 [2] 0c 0e [2] 10 09 [2] 0c 26 }

  condition:
    any of them
}