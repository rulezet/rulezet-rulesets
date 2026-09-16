rule TTP_XOR_QUAD_CurrentVersionRun_6631 {
  strings:
    $key_6631 = { 35 5e [2] 11 50 [2] 3a 7c [2] 14 5e [2] 00 45 [2] 0f 5f [2] 11 42 [2] 13 43 [2] 08 45 [2] 14 42 [2] 08 6d }

  condition:
    any of them
}