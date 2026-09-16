rule TTP_XOR_QUAD_CurrentVersionRun_c51c {
  strings:
    $key_c51c = { 96 73 [2] b2 7d [2] 99 51 [2] b7 73 [2] a3 68 [2] ac 72 [2] b2 6f [2] b0 6e [2] ab 68 [2] b7 6f [2] ab 40 }

  condition:
    any of them
}