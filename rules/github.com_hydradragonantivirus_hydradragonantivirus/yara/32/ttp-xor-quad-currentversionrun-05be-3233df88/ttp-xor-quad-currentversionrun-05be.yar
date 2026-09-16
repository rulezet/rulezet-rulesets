rule TTP_XOR_QUAD_CurrentVersionRun_05be {
  strings:
    $key_05be = { 56 d1 [2] 72 df [2] 59 f3 [2] 77 d1 [2] 63 ca [2] 6c d0 [2] 72 cd [2] 70 cc [2] 6b ca [2] 77 cd [2] 6b e2 }

  condition:
    any of them
}