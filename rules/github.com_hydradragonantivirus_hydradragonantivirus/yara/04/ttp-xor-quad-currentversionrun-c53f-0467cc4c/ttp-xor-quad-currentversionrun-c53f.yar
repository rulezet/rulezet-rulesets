rule TTP_XOR_QUAD_CurrentVersionRun_c53f {
  strings:
    $key_c53f = { 96 50 [2] b2 5e [2] 99 72 [2] b7 50 [2] a3 4b [2] ac 51 [2] b2 4c [2] b0 4d [2] ab 4b [2] b7 4c [2] ab 63 }

  condition:
    any of them
}