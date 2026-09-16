rule TTP_XOR_QUAD_CurrentVersionRun_00be {
  strings:
    $key_00be = { 53 d1 [2] 77 df [2] 5c f3 [2] 72 d1 [2] 66 ca [2] 69 d0 [2] 77 cd [2] 75 cc [2] 6e ca [2] 72 cd [2] 6e e2 }

  condition:
    any of them
}