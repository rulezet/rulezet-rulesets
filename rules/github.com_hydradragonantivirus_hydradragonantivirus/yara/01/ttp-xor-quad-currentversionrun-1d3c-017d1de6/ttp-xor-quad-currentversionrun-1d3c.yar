rule TTP_XOR_QUAD_CurrentVersionRun_1d3c {
  strings:
    $key_1d3c = { 4e 53 [2] 6a 5d [2] 41 71 [2] 6f 53 [2] 7b 48 [2] 74 52 [2] 6a 4f [2] 68 4e [2] 73 48 [2] 6f 4f [2] 73 60 }

  condition:
    any of them
}