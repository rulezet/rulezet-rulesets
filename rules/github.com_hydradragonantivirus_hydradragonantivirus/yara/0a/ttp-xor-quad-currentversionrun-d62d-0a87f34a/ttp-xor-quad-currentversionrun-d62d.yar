rule TTP_XOR_QUAD_CurrentVersionRun_d62d {
  strings:
    $key_d62d = { 85 42 [2] a1 4c [2] 8a 60 [2] a4 42 [2] b0 59 [2] bf 43 [2] a1 5e [2] a3 5f [2] b8 59 [2] a4 5e [2] b8 71 }

  condition:
    any of them
}