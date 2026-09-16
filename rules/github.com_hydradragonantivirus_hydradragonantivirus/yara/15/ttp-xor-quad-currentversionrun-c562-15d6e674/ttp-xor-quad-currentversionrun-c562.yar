rule TTP_XOR_QUAD_CurrentVersionRun_c562 {
  strings:
    $key_c562 = { 96 0d [2] b2 03 [2] 99 2f [2] b7 0d [2] a3 16 [2] ac 0c [2] b2 11 [2] b0 10 [2] ab 16 [2] b7 11 [2] ab 3e }

  condition:
    any of them
}