rule TTP_XOR_QUAD_CurrentVersionRun_2e33 {
  strings:
    $key_2e33 = { 7d 5c [2] 59 52 [2] 72 7e [2] 5c 5c [2] 48 47 [2] 47 5d [2] 59 40 [2] 5b 41 [2] 40 47 [2] 5c 40 [2] 40 6f }

  condition:
    any of them
}