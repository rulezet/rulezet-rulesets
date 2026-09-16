rule TTP_XOR_QUAD_CurrentVersionRun_292d {
  strings:
    $key_292d = { 7a 42 [2] 5e 4c [2] 75 60 [2] 5b 42 [2] 4f 59 [2] 40 43 [2] 5e 5e [2] 5c 5f [2] 47 59 [2] 5b 5e [2] 47 71 }

  condition:
    any of them
}