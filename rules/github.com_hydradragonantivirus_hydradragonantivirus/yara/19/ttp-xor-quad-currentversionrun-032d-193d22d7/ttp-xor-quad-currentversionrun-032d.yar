rule TTP_XOR_QUAD_CurrentVersionRun_032d {
  strings:
    $key_032d = { 50 42 [2] 74 4c [2] 5f 60 [2] 71 42 [2] 65 59 [2] 6a 43 [2] 74 5e [2] 76 5f [2] 6d 59 [2] 71 5e [2] 6d 71 }

  condition:
    any of them
}