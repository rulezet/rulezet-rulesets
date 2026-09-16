rule TTP_XOR_QUAD_CurrentVersionRun_572d {
  strings:
    $key_572d = { 04 42 [2] 20 4c [2] 0b 60 [2] 25 42 [2] 31 59 [2] 3e 43 [2] 20 5e [2] 22 5f [2] 39 59 [2] 25 5e [2] 39 71 }

  condition:
    any of them
}