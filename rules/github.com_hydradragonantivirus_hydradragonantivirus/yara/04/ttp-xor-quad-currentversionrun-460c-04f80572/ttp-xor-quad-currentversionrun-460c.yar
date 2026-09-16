rule TTP_XOR_QUAD_CurrentVersionRun_460c {
  strings:
    $key_460c = { 15 63 [2] 31 6d [2] 1a 41 [2] 34 63 [2] 20 78 [2] 2f 62 [2] 31 7f [2] 33 7e [2] 28 78 [2] 34 7f [2] 28 50 }

  condition:
    any of them
}