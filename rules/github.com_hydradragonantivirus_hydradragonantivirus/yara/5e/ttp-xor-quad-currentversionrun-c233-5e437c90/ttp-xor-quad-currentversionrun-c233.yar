rule TTP_XOR_QUAD_CurrentVersionRun_c233 {
  strings:
    $key_c233 = { 91 5c [2] b5 52 [2] 9e 7e [2] b0 5c [2] a4 47 [2] ab 5d [2] b5 40 [2] b7 41 [2] ac 47 [2] b0 40 [2] ac 6f }

  condition:
    any of them
}