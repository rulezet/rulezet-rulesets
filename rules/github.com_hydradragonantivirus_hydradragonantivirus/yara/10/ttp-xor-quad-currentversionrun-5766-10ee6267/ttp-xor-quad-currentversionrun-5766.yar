rule TTP_XOR_QUAD_CurrentVersionRun_5766 {
  strings:
    $key_5766 = { 04 09 [2] 20 07 [2] 0b 2b [2] 25 09 [2] 31 12 [2] 3e 08 [2] 20 15 [2] 22 14 [2] 39 12 [2] 25 15 [2] 39 3a }

  condition:
    any of them
}