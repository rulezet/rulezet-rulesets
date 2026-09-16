rule TTP_XOR_QUAD_CurrentVersionRun_c5e2 {
  strings:
    $key_c5e2 = { 96 8d [2] b2 83 [2] 99 af [2] b7 8d [2] a3 96 [2] ac 8c [2] b2 91 [2] b0 90 [2] ab 96 [2] b7 91 [2] ab be }

  condition:
    any of them
}