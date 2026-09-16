rule TTP_XOR_QUAD_CurrentVersionRun_2d3d {
  strings:
    $key_2d3d = { 7e 52 [2] 5a 5c [2] 71 70 [2] 5f 52 [2] 4b 49 [2] 44 53 [2] 5a 4e [2] 58 4f [2] 43 49 [2] 5f 4e [2] 43 61 }

  condition:
    any of them
}