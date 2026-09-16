rule TTP_XOR_QUAD_CurrentVersionRun_177a {
  strings:
    $key_177a = { 44 15 [2] 60 1b [2] 4b 37 [2] 65 15 [2] 71 0e [2] 7e 14 [2] 60 09 [2] 62 08 [2] 79 0e [2] 65 09 [2] 79 26 }

  condition:
    any of them
}