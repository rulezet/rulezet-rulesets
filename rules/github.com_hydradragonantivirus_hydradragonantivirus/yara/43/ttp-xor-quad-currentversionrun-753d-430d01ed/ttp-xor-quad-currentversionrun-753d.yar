rule TTP_XOR_QUAD_CurrentVersionRun_753d {
  strings:
    $key_753d = { 26 52 [2] 02 5c [2] 29 70 [2] 07 52 [2] 13 49 [2] 1c 53 [2] 02 4e [2] 00 4f [2] 1b 49 [2] 07 4e [2] 1b 61 }

  condition:
    any of them
}