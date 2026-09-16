rule TTP_XOR_QUAD_CurrentVersionRun_622d {
  strings:
    $key_622d = { 31 42 [2] 15 4c [2] 3e 60 [2] 10 42 [2] 04 59 [2] 0b 43 [2] 15 5e [2] 17 5f [2] 0c 59 [2] 10 5e [2] 0c 71 }

  condition:
    any of them
}