rule TTP_XOR_QUAD_CurrentVersionRun_7d3c {
  strings:
    $key_7d3c = { 2e 53 [2] 0a 5d [2] 21 71 [2] 0f 53 [2] 1b 48 [2] 14 52 [2] 0a 4f [2] 08 4e [2] 13 48 [2] 0f 4f [2] 13 60 }

  condition:
    any of them
}