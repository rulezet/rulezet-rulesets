rule TTP_XOR_QUAD_CurrentVersionRun_d70a {
  strings:
    $key_d70a = { 84 65 [2] a0 6b [2] 8b 47 [2] a5 65 [2] b1 7e [2] be 64 [2] a0 79 [2] a2 78 [2] b9 7e [2] a5 79 [2] b9 56 }

  condition:
    any of them
}