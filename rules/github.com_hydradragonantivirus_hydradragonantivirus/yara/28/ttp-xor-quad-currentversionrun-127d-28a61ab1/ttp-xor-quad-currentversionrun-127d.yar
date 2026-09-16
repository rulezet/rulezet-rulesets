rule TTP_XOR_QUAD_CurrentVersionRun_127d {
  strings:
    $key_127d = { 41 12 [2] 65 1c [2] 4e 30 [2] 60 12 [2] 74 09 [2] 7b 13 [2] 65 0e [2] 67 0f [2] 7c 09 [2] 60 0e [2] 7c 21 }

  condition:
    any of them
}