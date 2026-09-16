rule TTP_XOR_QUAD_CurrentVersionRun_276a {
  strings:
    $key_276a = { 74 05 [2] 50 0b [2] 7b 27 [2] 55 05 [2] 41 1e [2] 4e 04 [2] 50 19 [2] 52 18 [2] 49 1e [2] 55 19 [2] 49 36 }

  condition:
    any of them
}