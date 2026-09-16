rule TTP_XOR_QUAD_CurrentVersionRun_2d2a {
  strings:
    $key_2d2a = { 7e 45 [2] 5a 4b [2] 71 67 [2] 5f 45 [2] 4b 5e [2] 44 44 [2] 5a 59 [2] 58 58 [2] 43 5e [2] 5f 59 [2] 43 76 }

  condition:
    any of them
}