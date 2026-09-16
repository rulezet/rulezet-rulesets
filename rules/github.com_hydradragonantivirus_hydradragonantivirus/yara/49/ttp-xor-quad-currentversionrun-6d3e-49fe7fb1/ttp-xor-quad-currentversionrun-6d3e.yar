rule TTP_XOR_QUAD_CurrentVersionRun_6d3e {
  strings:
    $key_6d3e = { 3e 51 [2] 1a 5f [2] 31 73 [2] 1f 51 [2] 0b 4a [2] 04 50 [2] 1a 4d [2] 18 4c [2] 03 4a [2] 1f 4d [2] 03 62 }

  condition:
    any of them
}