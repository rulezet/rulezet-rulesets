rule TTP_XOR_QUAD_CurrentVersionRun_070c {
  strings:
    $key_070c = { 54 63 [2] 70 6d [2] 5b 41 [2] 75 63 [2] 61 78 [2] 6e 62 [2] 70 7f [2] 72 7e [2] 69 78 [2] 75 7f [2] 69 50 }

  condition:
    any of them
}