rule TTP_XOR_QUAD_CurrentVersionRun_246c {
  strings:
    $key_246c = { 77 03 [2] 53 0d [2] 78 21 [2] 56 03 [2] 42 18 [2] 4d 02 [2] 53 1f [2] 51 1e [2] 4a 18 [2] 56 1f [2] 4a 30 }

  condition:
    any of them
}