rule TTP_XOR_QUAD_CurrentVersionRun_d61f {
  strings:
    $key_d61f = { 85 70 [2] a1 7e [2] 8a 52 [2] a4 70 [2] b0 6b [2] bf 71 [2] a1 6c [2] a3 6d [2] b8 6b [2] a4 6c [2] b8 43 }

  condition:
    any of them
}