rule TTP_XOR_QUAD_CurrentVersionRun_30a3 {
  strings:
    $key_30a3 = { 63 cc [2] 47 c2 [2] 6c ee [2] 42 cc [2] 56 d7 [2] 59 cd [2] 47 d0 [2] 45 d1 [2] 5e d7 [2] 42 d0 [2] 5e ff }

  condition:
    any of them
}