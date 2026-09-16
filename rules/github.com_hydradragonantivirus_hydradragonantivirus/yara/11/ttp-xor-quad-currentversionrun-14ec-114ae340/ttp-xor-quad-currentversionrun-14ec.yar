rule TTP_XOR_QUAD_CurrentVersionRun_14ec {
  strings:
    $key_14ec = { 47 83 [2] 63 8d [2] 48 a1 [2] 66 83 [2] 72 98 [2] 7d 82 [2] 63 9f [2] 61 9e [2] 7a 98 [2] 66 9f [2] 7a b0 }

  condition:
    any of them
}