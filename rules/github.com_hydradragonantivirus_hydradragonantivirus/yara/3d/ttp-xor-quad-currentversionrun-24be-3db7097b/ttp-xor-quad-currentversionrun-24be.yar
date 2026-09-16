rule TTP_XOR_QUAD_CurrentVersionRun_24be {
  strings:
    $key_24be = { 77 d1 [2] 53 df [2] 78 f3 [2] 56 d1 [2] 42 ca [2] 4d d0 [2] 53 cd [2] 51 cc [2] 4a ca [2] 56 cd [2] 4a e2 }

  condition:
    any of them
}