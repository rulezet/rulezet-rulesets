rule TTP_XOR_QUAD_CurrentVersionRun_100a {
  strings:
    $key_100a = { 43 65 [2] 67 6b [2] 4c 47 [2] 62 65 [2] 76 7e [2] 79 64 [2] 67 79 [2] 65 78 [2] 7e 7e [2] 62 79 [2] 7e 56 }

  condition:
    any of them
}