rule TTP_XOR_QUAD_CurrentVersionRun_7201 {
  strings:
    $key_7201 = { 21 6e [2] 05 60 [2] 2e 4c [2] 00 6e [2] 14 75 [2] 1b 6f [2] 05 72 [2] 07 73 [2] 1c 75 [2] 00 72 [2] 1c 5d }

  condition:
    any of them
}