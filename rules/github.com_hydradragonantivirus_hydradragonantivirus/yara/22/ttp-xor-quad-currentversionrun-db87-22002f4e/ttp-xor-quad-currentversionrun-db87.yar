rule TTP_XOR_QUAD_CurrentVersionRun_db87 {
  strings:
    $key_db87 = { 88 e8 [2] ac e6 [2] 87 ca [2] a9 e8 [2] bd f3 [2] b2 e9 [2] ac f4 [2] ae f5 [2] b5 f3 [2] a9 f4 [2] b5 db }

  condition:
    any of them
}