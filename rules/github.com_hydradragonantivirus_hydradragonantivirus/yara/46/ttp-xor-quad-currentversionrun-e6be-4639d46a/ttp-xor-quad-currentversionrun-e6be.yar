rule TTP_XOR_QUAD_CurrentVersionRun_e6be {
  strings:
    $key_e6be = { b5 d1 [2] 91 df [2] ba f3 [2] 94 d1 [2] 80 ca [2] 8f d0 [2] 91 cd [2] 93 cc [2] 88 ca [2] 94 cd [2] 88 e2 }

  condition:
    any of them
}