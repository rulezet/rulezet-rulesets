rule TTP_XOR_QUAD_CurrentVersionRun_dcea {
  strings:
    $key_dcea = { 8f 85 [2] ab 8b [2] 80 a7 [2] ae 85 [2] ba 9e [2] b5 84 [2] ab 99 [2] a9 98 [2] b2 9e [2] ae 99 [2] b2 b6 }

  condition:
    any of them
}