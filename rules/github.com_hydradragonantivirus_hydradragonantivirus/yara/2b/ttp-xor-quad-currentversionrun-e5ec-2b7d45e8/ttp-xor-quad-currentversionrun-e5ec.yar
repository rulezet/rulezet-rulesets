rule TTP_XOR_QUAD_CurrentVersionRun_e5ec {
  strings:
    $key_e5ec = { b6 83 [2] 92 8d [2] b9 a1 [2] 97 83 [2] 83 98 [2] 8c 82 [2] 92 9f [2] 90 9e [2] 8b 98 [2] 97 9f [2] 8b b0 }

  condition:
    any of them
}