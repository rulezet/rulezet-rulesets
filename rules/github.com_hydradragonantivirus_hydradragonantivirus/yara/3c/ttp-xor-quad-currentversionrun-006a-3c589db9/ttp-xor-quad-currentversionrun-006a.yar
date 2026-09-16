rule TTP_XOR_QUAD_CurrentVersionRun_006a {
  strings:
    $key_006a = { 53 05 [2] 77 0b [2] 5c 27 [2] 72 05 [2] 66 1e [2] 69 04 [2] 77 19 [2] 75 18 [2] 6e 1e [2] 72 19 [2] 6e 36 }

  condition:
    any of them
}