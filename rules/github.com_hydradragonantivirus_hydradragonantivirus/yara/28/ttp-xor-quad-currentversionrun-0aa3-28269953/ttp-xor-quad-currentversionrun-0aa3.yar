rule TTP_XOR_QUAD_CurrentVersionRun_0aa3 {
  strings:
    $key_0aa3 = { 59 cc [2] 7d c2 [2] 56 ee [2] 78 cc [2] 6c d7 [2] 63 cd [2] 7d d0 [2] 7f d1 [2] 64 d7 [2] 78 d0 [2] 64 ff }

  condition:
    any of them
}