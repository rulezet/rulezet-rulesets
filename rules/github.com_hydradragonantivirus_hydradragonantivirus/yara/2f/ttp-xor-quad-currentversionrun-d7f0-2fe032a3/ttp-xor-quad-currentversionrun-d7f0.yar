rule TTP_XOR_QUAD_CurrentVersionRun_d7f0 {
  strings:
    $key_d7f0 = { 84 9f [2] a0 91 [2] 8b bd [2] a5 9f [2] b1 84 [2] be 9e [2] a0 83 [2] a2 82 [2] b9 84 [2] a5 83 [2] b9 ac }

  condition:
    any of them
}