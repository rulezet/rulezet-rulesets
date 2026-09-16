rule TTP_XOR_QUAD_CurrentVersionRun_662d {
  strings:
    $key_662d = { 35 42 [2] 11 4c [2] 3a 60 [2] 14 42 [2] 00 59 [2] 0f 43 [2] 11 5e [2] 13 5f [2] 08 59 [2] 14 5e [2] 08 71 }

  condition:
    any of them
}