rule TTP_XOR_QUAD_CurrentVersionRun_d62f {
  strings:
    $key_d62f = { 85 40 [2] a1 4e [2] 8a 62 [2] a4 40 [2] b0 5b [2] bf 41 [2] a1 5c [2] a3 5d [2] b8 5b [2] a4 5c [2] b8 73 }

  condition:
    any of them
}