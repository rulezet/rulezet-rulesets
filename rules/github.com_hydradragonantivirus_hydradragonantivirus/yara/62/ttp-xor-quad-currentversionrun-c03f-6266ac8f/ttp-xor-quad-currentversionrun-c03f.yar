rule TTP_XOR_QUAD_CurrentVersionRun_c03f {
  strings:
    $key_c03f = { 93 50 [2] b7 5e [2] 9c 72 [2] b2 50 [2] a6 4b [2] a9 51 [2] b7 4c [2] b5 4d [2] ae 4b [2] b2 4c [2] ae 63 }

  condition:
    any of them
}