rule TTP_XOR_QUAD_CurrentVersionRun_34be {
  strings:
    $key_34be = { 67 d1 [2] 43 df [2] 68 f3 [2] 46 d1 [2] 52 ca [2] 5d d0 [2] 43 cd [2] 41 cc [2] 5a ca [2] 46 cd [2] 5a e2 }

  condition:
    any of them
}