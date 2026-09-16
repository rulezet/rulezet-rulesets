rule TTP_XOR_QUAD_CurrentVersionRun_bfa3 {
  strings:
    $key_bfa3 = { ec cc [2] c8 c2 [2] e3 ee [2] cd cc [2] d9 d7 [2] d6 cd [2] c8 d0 [2] ca d1 [2] d1 d7 [2] cd d0 [2] d1 ff }

  condition:
    any of them
}