rule TTP_XOR_QUAD_CurrentVersionRun_c540 {
  strings:
    $key_c540 = { 96 2f [2] b2 21 [2] 99 0d [2] b7 2f [2] a3 34 [2] ac 2e [2] b2 33 [2] b0 32 [2] ab 34 [2] b7 33 [2] ab 1c }

  condition:
    any of them
}