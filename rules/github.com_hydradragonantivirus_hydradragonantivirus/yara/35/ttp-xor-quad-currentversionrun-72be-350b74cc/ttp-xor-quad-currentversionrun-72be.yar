rule TTP_XOR_QUAD_CurrentVersionRun_72be {
  strings:
    $key_72be = { 21 d1 [2] 05 df [2] 2e f3 [2] 00 d1 [2] 14 ca [2] 1b d0 [2] 05 cd [2] 07 cc [2] 1c ca [2] 00 cd [2] 1c e2 }

  condition:
    any of them
}