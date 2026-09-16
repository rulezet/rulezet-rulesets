rule TTP_XOR_QUAD_CurrentVersionRun_056a {
  strings:
    $key_056a = { 56 05 [2] 72 0b [2] 59 27 [2] 77 05 [2] 63 1e [2] 6c 04 [2] 72 19 [2] 70 18 [2] 6b 1e [2] 77 19 [2] 6b 36 }

  condition:
    any of them
}