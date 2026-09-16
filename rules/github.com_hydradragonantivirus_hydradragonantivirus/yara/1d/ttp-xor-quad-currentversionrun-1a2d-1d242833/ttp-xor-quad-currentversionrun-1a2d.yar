rule TTP_XOR_QUAD_CurrentVersionRun_1a2d {
  strings:
    $key_1a2d = { 49 42 [2] 6d 4c [2] 46 60 [2] 68 42 [2] 7c 59 [2] 73 43 [2] 6d 5e [2] 6f 5f [2] 74 59 [2] 68 5e [2] 74 71 }

  condition:
    any of them
}