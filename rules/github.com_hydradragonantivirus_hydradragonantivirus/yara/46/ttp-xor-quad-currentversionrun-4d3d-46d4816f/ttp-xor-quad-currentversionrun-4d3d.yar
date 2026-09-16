rule TTP_XOR_QUAD_CurrentVersionRun_4d3d {
  strings:
    $key_4d3d = { 1e 52 [2] 3a 5c [2] 11 70 [2] 3f 52 [2] 2b 49 [2] 24 53 [2] 3a 4e [2] 38 4f [2] 23 49 [2] 3f 4e [2] 23 61 }

  condition:
    any of them
}