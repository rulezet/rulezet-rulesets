rule TTP_XOR_QUAD_CurrentVersionRun_646b {
  strings:
    $key_646b = { 37 04 [2] 13 0a [2] 38 26 [2] 16 04 [2] 02 1f [2] 0d 05 [2] 13 18 [2] 11 19 [2] 0a 1f [2] 16 18 [2] 0a 37 }

  condition:
    any of them
}