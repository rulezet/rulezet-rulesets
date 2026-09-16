rule TTP_XOR_QUAD_CurrentVersionRun_3d3b {
  strings:
    $key_3d3b = { 6e 54 [2] 4a 5a [2] 61 76 [2] 4f 54 [2] 5b 4f [2] 54 55 [2] 4a 48 [2] 48 49 [2] 53 4f [2] 4f 48 [2] 53 67 }

  condition:
    any of them
}