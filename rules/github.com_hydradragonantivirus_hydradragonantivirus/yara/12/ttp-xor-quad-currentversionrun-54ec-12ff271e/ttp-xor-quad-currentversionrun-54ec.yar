rule TTP_XOR_QUAD_CurrentVersionRun_54ec {
  strings:
    $key_54ec = { 07 83 [2] 23 8d [2] 08 a1 [2] 26 83 [2] 32 98 [2] 3d 82 [2] 23 9f [2] 21 9e [2] 3a 98 [2] 26 9f [2] 3a b0 }

  condition:
    any of them
}