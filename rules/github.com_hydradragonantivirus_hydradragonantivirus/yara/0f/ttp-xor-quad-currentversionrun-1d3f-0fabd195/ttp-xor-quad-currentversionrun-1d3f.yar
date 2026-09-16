rule TTP_XOR_QUAD_CurrentVersionRun_1d3f {
  strings:
    $key_1d3f = { 4e 50 [2] 6a 5e [2] 41 72 [2] 6f 50 [2] 7b 4b [2] 74 51 [2] 6a 4c [2] 68 4d [2] 73 4b [2] 6f 4c [2] 73 63 }

  condition:
    any of them
}