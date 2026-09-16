rule TTP_XOR_QUAD_CurrentVersionRun_21be {
  strings:
    $key_21be = { 72 d1 [2] 56 df [2] 7d f3 [2] 53 d1 [2] 47 ca [2] 48 d0 [2] 56 cd [2] 54 cc [2] 4f ca [2] 53 cd [2] 4f e2 }

  condition:
    any of them
}