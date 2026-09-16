rule TTP_XOR_QUAD_CurrentVersionRun_d0eb {
  strings:
    $key_d0eb = { 83 84 [2] a7 8a [2] 8c a6 [2] a2 84 [2] b6 9f [2] b9 85 [2] a7 98 [2] a5 99 [2] be 9f [2] a2 98 [2] be b7 }

  condition:
    any of them
}