rule TTP_XOR_QUAD_CurrentVersionRun_3e33 {
  strings:
    $key_3e33 = { 6d 5c [2] 49 52 [2] 62 7e [2] 4c 5c [2] 58 47 [2] 57 5d [2] 49 40 [2] 4b 41 [2] 50 47 [2] 4c 40 [2] 50 6f }

  condition:
    any of them
}