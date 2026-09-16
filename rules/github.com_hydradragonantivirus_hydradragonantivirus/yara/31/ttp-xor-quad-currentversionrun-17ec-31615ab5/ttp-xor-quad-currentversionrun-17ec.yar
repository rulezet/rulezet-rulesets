rule TTP_XOR_QUAD_CurrentVersionRun_17ec {
  strings:
    $key_17ec = { 44 83 [2] 60 8d [2] 4b a1 [2] 65 83 [2] 71 98 [2] 7e 82 [2] 60 9f [2] 62 9e [2] 79 98 [2] 65 9f [2] 79 b0 }

  condition:
    any of them
}