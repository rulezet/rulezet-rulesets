rule TTP_XOR_QUAD_CurrentVersionRun_d76f {
  strings:
    $key_d76f = { 84 00 [2] a0 0e [2] 8b 22 [2] a5 00 [2] b1 1b [2] be 01 [2] a0 1c [2] a2 1d [2] b9 1b [2] a5 1c [2] b9 33 }

  condition:
    any of them
}