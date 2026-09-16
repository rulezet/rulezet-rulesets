rule TTP_XOR_QUAD_CurrentVersionRun_35be {
  strings:
    $key_35be = { 66 d1 [2] 42 df [2] 69 f3 [2] 47 d1 [2] 53 ca [2] 5c d0 [2] 42 cd [2] 40 cc [2] 5b ca [2] 47 cd [2] 5b e2 }

  condition:
    any of them
}