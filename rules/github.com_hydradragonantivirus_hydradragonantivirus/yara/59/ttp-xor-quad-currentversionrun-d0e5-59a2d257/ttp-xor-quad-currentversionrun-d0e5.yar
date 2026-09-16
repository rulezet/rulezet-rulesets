rule TTP_XOR_QUAD_CurrentVersionRun_d0e5 {
  strings:
    $key_d0e5 = { 83 8a [2] a7 84 [2] 8c a8 [2] a2 8a [2] b6 91 [2] b9 8b [2] a7 96 [2] a5 97 [2] be 91 [2] a2 96 [2] be b9 }

  condition:
    any of them
}