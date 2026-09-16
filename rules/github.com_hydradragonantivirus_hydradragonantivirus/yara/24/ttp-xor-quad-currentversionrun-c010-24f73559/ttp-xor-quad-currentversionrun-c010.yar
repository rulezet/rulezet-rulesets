rule TTP_XOR_QUAD_CurrentVersionRun_c010 {
  strings:
    $key_c010 = { 93 7f [2] b7 71 [2] 9c 5d [2] b2 7f [2] a6 64 [2] a9 7e [2] b7 63 [2] b5 62 [2] ae 64 [2] b2 63 [2] ae 4c }

  condition:
    any of them
}