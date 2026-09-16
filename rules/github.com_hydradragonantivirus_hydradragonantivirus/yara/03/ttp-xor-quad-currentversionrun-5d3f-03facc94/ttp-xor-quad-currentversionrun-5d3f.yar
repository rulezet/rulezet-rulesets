rule TTP_XOR_QUAD_CurrentVersionRun_5d3f {
  strings:
    $key_5d3f = { 0e 50 [2] 2a 5e [2] 01 72 [2] 2f 50 [2] 3b 4b [2] 34 51 [2] 2a 4c [2] 28 4d [2] 33 4b [2] 2f 4c [2] 33 63 }

  condition:
    any of them
}