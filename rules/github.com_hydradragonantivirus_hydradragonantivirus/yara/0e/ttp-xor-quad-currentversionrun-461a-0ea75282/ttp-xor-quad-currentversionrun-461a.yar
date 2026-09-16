rule TTP_XOR_QUAD_CurrentVersionRun_461a {
  strings:
    $key_461a = { 15 75 [2] 31 7b [2] 1a 57 [2] 34 75 [2] 20 6e [2] 2f 74 [2] 31 69 [2] 33 68 [2] 28 6e [2] 34 69 [2] 28 46 }

  condition:
    any of them
}