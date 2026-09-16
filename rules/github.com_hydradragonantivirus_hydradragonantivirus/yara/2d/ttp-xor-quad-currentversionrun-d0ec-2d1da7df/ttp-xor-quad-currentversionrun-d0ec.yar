rule TTP_XOR_QUAD_CurrentVersionRun_d0ec {
  strings:
    $key_d0ec = { 83 83 [2] a7 8d [2] 8c a1 [2] a2 83 [2] b6 98 [2] b9 82 [2] a7 9f [2] a5 9e [2] be 98 [2] a2 9f [2] be b0 }

  condition:
    any of them
}