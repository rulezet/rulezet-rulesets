rule TTP_XOR_QUAD_CurrentVersionRun_d11f {
  strings:
    $key_d11f = { 82 70 [2] a6 7e [2] 8d 52 [2] a3 70 [2] b7 6b [2] b8 71 [2] a6 6c [2] a4 6d [2] bf 6b [2] a3 6c [2] bf 43 }

  condition:
    any of them
}