rule TTP_XOR_QUAD_CurrentVersionRun_2d3e {
  strings:
    $key_2d3e = { 7e 51 [2] 5a 5f [2] 71 73 [2] 5f 51 [2] 4b 4a [2] 44 50 [2] 5a 4d [2] 58 4c [2] 43 4a [2] 5f 4d [2] 43 62 }

  condition:
    any of them
}