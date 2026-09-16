rule TTP_XOR_QUAD_CurrentVersionRun_d11c {
  strings:
    $key_d11c = { 82 73 [2] a6 7d [2] 8d 51 [2] a3 73 [2] b7 68 [2] b8 72 [2] a6 6f [2] a4 6e [2] bf 68 [2] a3 6f [2] bf 40 }

  condition:
    any of them
}