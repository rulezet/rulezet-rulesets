rule TTP_XOR_QUAD_CurrentVersionRun_44ec {
  strings:
    $key_44ec = { 17 83 [2] 33 8d [2] 18 a1 [2] 36 83 [2] 22 98 [2] 2d 82 [2] 33 9f [2] 31 9e [2] 2a 98 [2] 36 9f [2] 2a b0 }

  condition:
    any of them
}