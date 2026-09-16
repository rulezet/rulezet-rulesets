rule TTP_XOR_QUAD_CurrentVersionRun_f4be {
  strings:
    $key_f4be = { a7 d1 [2] 83 df [2] a8 f3 [2] 86 d1 [2] 92 ca [2] 9d d0 [2] 83 cd [2] 81 cc [2] 9a ca [2] 86 cd [2] 9a e2 }

  condition:
    any of them
}