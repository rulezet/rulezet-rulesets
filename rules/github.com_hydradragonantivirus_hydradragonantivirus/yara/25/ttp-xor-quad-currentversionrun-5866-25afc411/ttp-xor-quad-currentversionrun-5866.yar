rule TTP_XOR_QUAD_CurrentVersionRun_5866 {
  strings:
    $key_5866 = { 0b 09 [2] 2f 07 [2] 04 2b [2] 2a 09 [2] 3e 12 [2] 31 08 [2] 2f 15 [2] 2d 14 [2] 36 12 [2] 2a 15 [2] 36 3a }

  condition:
    any of them
}