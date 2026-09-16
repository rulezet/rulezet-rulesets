rule TTP_XOR_QUAD_CurrentVersionRun_c02f {
  strings:
    $key_c02f = { 93 40 [2] b7 4e [2] 9c 62 [2] b2 40 [2] a6 5b [2] a9 41 [2] b7 5c [2] b5 5d [2] ae 5b [2] b2 5c [2] ae 73 }

  condition:
    any of them
}