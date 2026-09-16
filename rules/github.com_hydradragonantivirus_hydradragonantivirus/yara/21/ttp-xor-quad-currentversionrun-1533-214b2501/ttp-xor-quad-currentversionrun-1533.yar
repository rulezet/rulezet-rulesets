rule TTP_XOR_QUAD_CurrentVersionRun_1533 {
  strings:
    $key_1533 = { 46 5c [2] 62 52 [2] 49 7e [2] 67 5c [2] 73 47 [2] 7c 5d [2] 62 40 [2] 60 41 [2] 7b 47 [2] 67 40 [2] 7b 6f }

  condition:
    any of them
}