rule TTP_XOR_QUAD_CurrentVersionRun_3433 {
  strings:
    $key_3433 = { 67 5c [2] 43 52 [2] 68 7e [2] 46 5c [2] 52 47 [2] 5d 5d [2] 43 40 [2] 41 41 [2] 5a 47 [2] 46 40 [2] 5a 6f }

  condition:
    any of them
}