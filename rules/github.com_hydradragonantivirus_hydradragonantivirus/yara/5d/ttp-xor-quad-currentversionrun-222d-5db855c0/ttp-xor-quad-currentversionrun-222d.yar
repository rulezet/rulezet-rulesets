rule TTP_XOR_QUAD_CurrentVersionRun_222d {
  strings:
    $key_222d = { 71 42 [2] 55 4c [2] 7e 60 [2] 50 42 [2] 44 59 [2] 4b 43 [2] 55 5e [2] 57 5f [2] 4c 59 [2] 50 5e [2] 4c 71 }

  condition:
    any of them
}