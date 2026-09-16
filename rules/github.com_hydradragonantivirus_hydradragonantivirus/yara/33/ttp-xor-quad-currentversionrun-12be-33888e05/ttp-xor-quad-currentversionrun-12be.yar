rule TTP_XOR_QUAD_CurrentVersionRun_12be {
  strings:
    $key_12be = { 41 d1 [2] 65 df [2] 4e f3 [2] 60 d1 [2] 74 ca [2] 7b d0 [2] 65 cd [2] 67 cc [2] 7c ca [2] 60 cd [2] 7c e2 }

  condition:
    any of them
}