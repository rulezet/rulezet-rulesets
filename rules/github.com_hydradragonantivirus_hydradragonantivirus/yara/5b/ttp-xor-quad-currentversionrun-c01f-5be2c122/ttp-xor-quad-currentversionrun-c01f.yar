rule TTP_XOR_QUAD_CurrentVersionRun_c01f {
  strings:
    $key_c01f = { 93 70 [2] b7 7e [2] 9c 52 [2] b2 70 [2] a6 6b [2] a9 71 [2] b7 6c [2] b5 6d [2] ae 6b [2] b2 6c [2] ae 43 }

  condition:
    any of them
}