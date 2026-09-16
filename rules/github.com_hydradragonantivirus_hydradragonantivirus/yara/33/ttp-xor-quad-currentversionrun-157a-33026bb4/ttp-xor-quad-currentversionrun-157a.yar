rule TTP_XOR_QUAD_CurrentVersionRun_157a {
  strings:
    $key_157a = { 46 15 [2] 62 1b [2] 49 37 [2] 67 15 [2] 73 0e [2] 7c 14 [2] 62 09 [2] 60 08 [2] 7b 0e [2] 67 09 [2] 7b 26 }

  condition:
    any of them
}