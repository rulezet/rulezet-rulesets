rule TTP_XOR_QUAD_CurrentVersionRun_0d3e {
  strings:
    $key_0d3e = { 5e 51 [2] 7a 5f [2] 51 73 [2] 7f 51 [2] 6b 4a [2] 64 50 [2] 7a 4d [2] 78 4c [2] 63 4a [2] 7f 4d [2] 63 62 }

  condition:
    any of them
}