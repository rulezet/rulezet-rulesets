rule TTP_XOR_QUAD_CurrentVersionRun_c54a {
  strings:
    $key_c54a = { 96 25 [2] b2 2b [2] 99 07 [2] b7 25 [2] a3 3e [2] ac 24 [2] b2 39 [2] b0 38 [2] ab 3e [2] b7 39 [2] ab 16 }

  condition:
    any of them
}