rule TTP_XOR_QUAD_CurrentVersionRun_6d21 {
  strings:
    $key_6d21 = { 3e 4e [2] 1a 40 [2] 31 6c [2] 1f 4e [2] 0b 55 [2] 04 4f [2] 1a 52 [2] 18 53 [2] 03 55 [2] 1f 52 [2] 03 7d }

  condition:
    any of them
}