rule TTP_XOR_QUAD_CurrentVersionRun_0d3c {
  strings:
    $key_0d3c = { 5e 53 [2] 7a 5d [2] 51 71 [2] 7f 53 [2] 6b 48 [2] 64 52 [2] 7a 4f [2] 78 4e [2] 63 48 [2] 7f 4f [2] 63 60 }

  condition:
    any of them
}