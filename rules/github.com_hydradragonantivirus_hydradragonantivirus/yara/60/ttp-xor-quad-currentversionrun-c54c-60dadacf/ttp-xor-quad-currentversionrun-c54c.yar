rule TTP_XOR_QUAD_CurrentVersionRun_c54c {
  strings:
    $key_c54c = { 96 23 [2] b2 2d [2] 99 01 [2] b7 23 [2] a3 38 [2] ac 22 [2] b2 3f [2] b0 3e [2] ab 38 [2] b7 3f [2] ab 10 }

  condition:
    any of them
}