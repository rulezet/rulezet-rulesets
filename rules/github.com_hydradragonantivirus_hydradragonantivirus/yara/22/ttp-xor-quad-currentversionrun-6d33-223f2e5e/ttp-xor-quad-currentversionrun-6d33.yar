rule TTP_XOR_QUAD_CurrentVersionRun_6d33 {
  strings:
    $key_6d33 = { 3e 5c [2] 1a 52 [2] 31 7e [2] 1f 5c [2] 0b 47 [2] 04 5d [2] 1a 40 [2] 18 41 [2] 03 47 [2] 1f 40 [2] 03 6f }

  condition:
    any of them
}