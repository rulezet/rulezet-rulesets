rule TTP_XOR_QUAD_CurrentVersionRun_3c6a {
  strings:
    $key_3c6a = { 6f 05 [2] 4b 0b [2] 60 27 [2] 4e 05 [2] 5a 1e [2] 55 04 [2] 4b 19 [2] 49 18 [2] 52 1e [2] 4e 19 [2] 52 36 }

  condition:
    any of them
}