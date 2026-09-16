rule TTP_XOR_QUAD_CurrentVersionRun_2d3c {
  strings:
    $key_2d3c = { 7e 53 [2] 5a 5d [2] 71 71 [2] 5f 53 [2] 4b 48 [2] 44 52 [2] 5a 4f [2] 58 4e [2] 43 48 [2] 5f 4f [2] 43 60 }

  condition:
    any of them
}