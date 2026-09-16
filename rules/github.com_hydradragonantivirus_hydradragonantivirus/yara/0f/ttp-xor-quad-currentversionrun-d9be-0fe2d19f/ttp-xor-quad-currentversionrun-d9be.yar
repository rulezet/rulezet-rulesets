rule TTP_XOR_QUAD_CurrentVersionRun_d9be {
  strings:
    $key_d9be = { 8a d1 [2] ae df [2] 85 f3 [2] ab d1 [2] bf ca [2] b0 d0 [2] ae cd [2] ac cc [2] b7 ca [2] ab cd [2] b7 e2 }

  condition:
    any of them
}