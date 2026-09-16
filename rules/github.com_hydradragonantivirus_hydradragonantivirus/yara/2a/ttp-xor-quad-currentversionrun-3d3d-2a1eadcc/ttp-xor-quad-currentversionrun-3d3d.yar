rule TTP_XOR_QUAD_CurrentVersionRun_3d3d {
  strings:
    $key_3d3d = { 6e 52 [2] 4a 5c [2] 61 70 [2] 4f 52 [2] 5b 49 [2] 54 53 [2] 4a 4e [2] 48 4f [2] 53 49 [2] 4f 4e [2] 53 61 }

  condition:
    any of them
}