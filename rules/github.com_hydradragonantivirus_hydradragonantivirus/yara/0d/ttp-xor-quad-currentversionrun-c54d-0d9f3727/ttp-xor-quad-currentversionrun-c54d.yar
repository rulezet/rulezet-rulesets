rule TTP_XOR_QUAD_CurrentVersionRun_c54d {
  strings:
    $key_c54d = { 96 22 [2] b2 2c [2] 99 00 [2] b7 22 [2] a3 39 [2] ac 23 [2] b2 3e [2] b0 3f [2] ab 39 [2] b7 3e [2] ab 11 }

  condition:
    any of them
}