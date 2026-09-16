rule TTP_XOR_QUAD_CurrentVersionRun_5d3c {
  strings:
    $key_5d3c = { 0e 53 [2] 2a 5d [2] 01 71 [2] 2f 53 [2] 3b 48 [2] 34 52 [2] 2a 4f [2] 28 4e [2] 33 48 [2] 2f 4f [2] 33 60 }

  condition:
    any of them
}