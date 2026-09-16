rule TTP_XOR_QUAD_CurrentVersionRun_756a {
  strings:
    $key_756a = { 26 05 [2] 02 0b [2] 29 27 [2] 07 05 [2] 13 1e [2] 1c 04 [2] 02 19 [2] 00 18 [2] 1b 1e [2] 07 19 [2] 1b 36 }

  condition:
    any of them
}