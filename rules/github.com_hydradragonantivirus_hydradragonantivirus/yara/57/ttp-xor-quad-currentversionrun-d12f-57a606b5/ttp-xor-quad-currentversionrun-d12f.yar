rule TTP_XOR_QUAD_CurrentVersionRun_d12f {
  strings:
    $key_d12f = { 82 40 [2] a6 4e [2] 8d 62 [2] a3 40 [2] b7 5b [2] b8 41 [2] a6 5c [2] a4 5d [2] bf 5b [2] a3 5c [2] bf 73 }

  condition:
    any of them
}