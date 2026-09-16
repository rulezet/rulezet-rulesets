rule TTP_XOR_QUAD_CurrentVersionRun_d11d {
  strings:
    $key_d11d = { 82 72 [2] a6 7c [2] 8d 50 [2] a3 72 [2] b7 69 [2] b8 73 [2] a6 6e [2] a4 6f [2] bf 69 [2] a3 6e [2] bf 41 }

  condition:
    any of them
}