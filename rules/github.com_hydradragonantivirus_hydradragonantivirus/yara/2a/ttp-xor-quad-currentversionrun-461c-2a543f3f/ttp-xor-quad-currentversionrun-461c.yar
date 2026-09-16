rule TTP_XOR_QUAD_CurrentVersionRun_461c {
  strings:
    $key_461c = { 15 73 [2] 31 7d [2] 1a 51 [2] 34 73 [2] 20 68 [2] 2f 72 [2] 31 6f [2] 33 6e [2] 28 68 [2] 34 6f [2] 28 40 }

  condition:
    any of them
}