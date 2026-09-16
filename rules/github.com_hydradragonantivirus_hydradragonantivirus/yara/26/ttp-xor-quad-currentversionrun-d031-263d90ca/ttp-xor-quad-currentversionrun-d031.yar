rule TTP_XOR_QUAD_CurrentVersionRun_d031 {
  strings:
    $key_d031 = { 83 5e [2] a7 50 [2] 8c 7c [2] a2 5e [2] b6 45 [2] b9 5f [2] a7 42 [2] a5 43 [2] be 45 [2] a2 42 [2] be 6d }

  condition:
    any of them
}