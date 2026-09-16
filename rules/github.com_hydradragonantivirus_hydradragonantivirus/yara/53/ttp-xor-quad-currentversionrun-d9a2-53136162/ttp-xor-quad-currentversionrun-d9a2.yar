rule TTP_XOR_QUAD_CurrentVersionRun_d9a2 {
  strings:
    $key_d9a2 = { 8a cd [2] ae c3 [2] 85 ef [2] ab cd [2] bf d6 [2] b0 cc [2] ae d1 [2] ac d0 [2] b7 d6 [2] ab d1 [2] b7 fe }

  condition:
    any of them
}