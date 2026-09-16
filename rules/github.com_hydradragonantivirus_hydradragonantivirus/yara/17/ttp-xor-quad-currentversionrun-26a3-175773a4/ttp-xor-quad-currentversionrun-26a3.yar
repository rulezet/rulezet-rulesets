rule TTP_XOR_QUAD_CurrentVersionRun_26a3 {
  strings:
    $key_26a3 = { 75 cc [2] 51 c2 [2] 7a ee [2] 54 cc [2] 40 d7 [2] 4f cd [2] 51 d0 [2] 53 d1 [2] 48 d7 [2] 54 d0 [2] 48 ff }

  condition:
    any of them
}