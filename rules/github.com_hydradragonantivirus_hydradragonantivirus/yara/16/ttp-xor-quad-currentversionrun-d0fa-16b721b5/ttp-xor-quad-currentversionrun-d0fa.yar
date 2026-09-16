rule TTP_XOR_QUAD_CurrentVersionRun_d0fa {
  strings:
    $key_d0fa = { 83 95 [2] a7 9b [2] 8c b7 [2] a2 95 [2] b6 8e [2] b9 94 [2] a7 89 [2] a5 88 [2] be 8e [2] a2 89 [2] be a6 }

  condition:
    any of them
}