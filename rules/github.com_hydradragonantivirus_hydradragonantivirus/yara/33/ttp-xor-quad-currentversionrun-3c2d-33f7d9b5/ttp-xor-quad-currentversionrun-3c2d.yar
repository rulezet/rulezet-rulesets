rule TTP_XOR_QUAD_CurrentVersionRun_3c2d {
  strings:
    $key_3c2d = { 6f 42 [2] 4b 4c [2] 60 60 [2] 4e 42 [2] 5a 59 [2] 55 43 [2] 4b 5e [2] 49 5f [2] 52 59 [2] 4e 5e [2] 52 71 }

  condition:
    any of them
}