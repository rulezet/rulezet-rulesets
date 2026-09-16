rule TTP_XOR_QUAD_CurrentVersionRun_51ec {
  strings:
    $key_51ec = { 02 83 [2] 26 8d [2] 0d a1 [2] 23 83 [2] 37 98 [2] 38 82 [2] 26 9f [2] 24 9e [2] 3f 98 [2] 23 9f [2] 3f b0 }

  condition:
    any of them
}