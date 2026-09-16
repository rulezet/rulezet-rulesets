rule TTP_XOR_QUAD_CurrentVersionRun_3766 {
  strings:
    $key_3766 = { 64 09 [2] 40 07 [2] 6b 2b [2] 45 09 [2] 51 12 [2] 5e 08 [2] 40 15 [2] 42 14 [2] 59 12 [2] 45 15 [2] 59 3a }

  condition:
    any of them
}