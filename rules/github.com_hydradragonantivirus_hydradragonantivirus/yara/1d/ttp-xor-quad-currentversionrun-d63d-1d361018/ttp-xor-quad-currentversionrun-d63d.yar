rule TTP_XOR_QUAD_CurrentVersionRun_d63d {
  strings:
    $key_d63d = { 85 52 [2] a1 5c [2] 8a 70 [2] a4 52 [2] b0 49 [2] bf 53 [2] a1 4e [2] a3 4f [2] b8 49 [2] a4 4e [2] b8 61 }

  condition:
    any of them
}