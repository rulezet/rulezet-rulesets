rule TTP_XOR_QUAD_CurrentVersionRun_c57d {
  strings:
    $key_c57d = { 96 12 [2] b2 1c [2] 99 30 [2] b7 12 [2] a3 09 [2] ac 13 [2] b2 0e [2] b0 0f [2] ab 09 [2] b7 0e [2] ab 21 }

  condition:
    any of them
}