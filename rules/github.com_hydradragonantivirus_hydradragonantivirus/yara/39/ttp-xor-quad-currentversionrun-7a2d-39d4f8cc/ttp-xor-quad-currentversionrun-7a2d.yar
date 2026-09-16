rule TTP_XOR_QUAD_CurrentVersionRun_7a2d {
  strings:
    $key_7a2d = { 29 42 [2] 0d 4c [2] 26 60 [2] 08 42 [2] 1c 59 [2] 13 43 [2] 0d 5e [2] 0f 5f [2] 14 59 [2] 08 5e [2] 14 71 }

  condition:
    any of them
}