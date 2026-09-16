rule TTP_XOR_QUAD_CurrentVersionRun_d72b {
  strings:
    $key_d72b = { 84 44 [2] a0 4a [2] 8b 66 [2] a5 44 [2] b1 5f [2] be 45 [2] a0 58 [2] a2 59 [2] b9 5f [2] a5 58 [2] b9 77 }

  condition:
    any of them
}