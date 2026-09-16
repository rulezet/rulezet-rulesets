rule TTP_XOR_QUAD_CurrentVersionRun_c510 {
  strings:
    $key_c510 = { 96 7f [2] b2 71 [2] 99 5d [2] b7 7f [2] a3 64 [2] ac 7e [2] b2 63 [2] b0 62 [2] ab 64 [2] b7 63 [2] ab 4c }

  condition:
    any of them
}