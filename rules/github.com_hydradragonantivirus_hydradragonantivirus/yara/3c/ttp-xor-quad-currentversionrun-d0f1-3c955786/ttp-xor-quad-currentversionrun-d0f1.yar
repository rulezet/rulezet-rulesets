rule TTP_XOR_QUAD_CurrentVersionRun_d0f1 {
  strings:
    $key_d0f1 = { 83 9e [2] a7 90 [2] 8c bc [2] a2 9e [2] b6 85 [2] b9 9f [2] a7 82 [2] a5 83 [2] be 85 [2] a2 82 [2] be ad }

  condition:
    any of them
}