rule TTP_XOR_QUAD_CurrentVersionRun_1f2a {
  strings:
    $key_1f2a = { 4c 45 [2] 68 4b [2] 43 67 [2] 6d 45 [2] 79 5e [2] 76 44 [2] 68 59 [2] 6a 58 [2] 71 5e [2] 6d 59 [2] 71 76 }

  condition:
    any of them
}