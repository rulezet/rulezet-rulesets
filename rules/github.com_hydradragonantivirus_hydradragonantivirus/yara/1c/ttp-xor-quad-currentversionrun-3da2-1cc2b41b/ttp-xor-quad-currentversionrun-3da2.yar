rule TTP_XOR_QUAD_CurrentVersionRun_3da2 {
  strings:
    $key_3da2 = { 6e cd [2] 4a c3 [2] 61 ef [2] 4f cd [2] 5b d6 [2] 54 cc [2] 4a d1 [2] 48 d0 [2] 53 d6 [2] 4f d1 [2] 53 fe }

  condition:
    any of them
}