rule TTP_XOR_QUAD_CurrentVersionRun_de26 {
  strings:
    $key_de26 = { 8d 49 [2] a9 47 [2] 82 6b [2] ac 49 [2] b8 52 [2] b7 48 [2] a9 55 [2] ab 54 [2] b0 52 [2] ac 55 [2] b0 7a }

  condition:
    any of them
}