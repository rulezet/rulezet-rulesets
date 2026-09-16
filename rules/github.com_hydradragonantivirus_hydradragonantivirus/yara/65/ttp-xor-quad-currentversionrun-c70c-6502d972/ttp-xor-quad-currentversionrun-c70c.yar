rule TTP_XOR_QUAD_CurrentVersionRun_c70c {
  strings:
    $key_c70c = { 94 63 [2] b0 6d [2] 9b 41 [2] b5 63 [2] a1 78 [2] ae 62 [2] b0 7f [2] b2 7e [2] a9 78 [2] b5 7f [2] a9 50 }

  condition:
    any of them
}