rule TTP_XOR_QUAD_CurrentVersionRun_62be {
  strings:
    $key_62be = { 31 d1 [2] 15 df [2] 3e f3 [2] 10 d1 [2] 04 ca [2] 0b d0 [2] 15 cd [2] 17 cc [2] 0c ca [2] 10 cd [2] 0c e2 }

  condition:
    any of them
}