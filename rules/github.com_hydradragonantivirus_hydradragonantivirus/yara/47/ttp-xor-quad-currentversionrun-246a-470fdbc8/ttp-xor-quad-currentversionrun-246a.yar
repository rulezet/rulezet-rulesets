rule TTP_XOR_QUAD_CurrentVersionRun_246a {
  strings:
    $key_246a = { 77 05 [2] 53 0b [2] 78 27 [2] 56 05 [2] 42 1e [2] 4d 04 [2] 53 19 [2] 51 18 [2] 4a 1e [2] 56 19 [2] 4a 36 }

  condition:
    any of them
}