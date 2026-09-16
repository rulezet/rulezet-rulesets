rule TTP_XOR_QUAD_CurrentVersionRun_2ba3 {
  strings:
    $key_2ba3 = { 78 cc [2] 5c c2 [2] 77 ee [2] 59 cc [2] 4d d7 [2] 42 cd [2] 5c d0 [2] 5e d1 [2] 45 d7 [2] 59 d0 [2] 45 ff }

  condition:
    any of them
}