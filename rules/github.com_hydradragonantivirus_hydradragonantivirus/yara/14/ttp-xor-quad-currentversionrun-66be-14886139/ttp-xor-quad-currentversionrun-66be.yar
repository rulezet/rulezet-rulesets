rule TTP_XOR_QUAD_CurrentVersionRun_66be {
  strings:
    $key_66be = { 35 d1 [2] 11 df [2] 3a f3 [2] 14 d1 [2] 00 ca [2] 0f d0 [2] 11 cd [2] 13 cc [2] 08 ca [2] 14 cd [2] 08 e2 }

  condition:
    any of them
}