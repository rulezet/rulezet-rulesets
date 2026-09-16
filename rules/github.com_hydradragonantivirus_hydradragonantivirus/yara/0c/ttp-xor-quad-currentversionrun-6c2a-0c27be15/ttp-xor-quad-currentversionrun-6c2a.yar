rule TTP_XOR_QUAD_CurrentVersionRun_6c2a {
  strings:
    $key_6c2a = { 3f 45 [2] 1b 4b [2] 30 67 [2] 1e 45 [2] 0a 5e [2] 05 44 [2] 1b 59 [2] 19 58 [2] 02 5e [2] 1e 59 [2] 02 76 }

  condition:
    any of them
}