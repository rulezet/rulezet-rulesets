rule TTP_XOR_QUAD_CurrentVersionRun_c5a2 {
  strings:
    $key_c5a2 = { 96 cd [2] b2 c3 [2] 99 ef [2] b7 cd [2] a3 d6 [2] ac cc [2] b2 d1 [2] b0 d0 [2] ab d6 [2] b7 d1 [2] ab fe }

  condition:
    any of them
}