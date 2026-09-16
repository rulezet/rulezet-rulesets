rule TTP_XOR_QUAD_CurrentVersionRun_d62a {
  strings:
    $key_d62a = { 85 45 [2] a1 4b [2] 8a 67 [2] a4 45 [2] b0 5e [2] bf 44 [2] a1 59 [2] a3 58 [2] b8 5e [2] a4 59 [2] b8 76 }

  condition:
    any of them
}