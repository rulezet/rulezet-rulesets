rule TTP_XOR_QUAD_CurrentVersionRun_3d3f {
  strings:
    $key_3d3f = { 6e 50 [2] 4a 5e [2] 61 72 [2] 4f 50 [2] 5b 4b [2] 54 51 [2] 4a 4c [2] 48 4d [2] 53 4b [2] 4f 4c [2] 53 63 }

  condition:
    any of them
}