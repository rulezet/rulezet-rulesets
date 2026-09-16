rule TTP_XOR_QUAD_CurrentVersionRun_356c {
  strings:
    $key_356c = { 66 03 [2] 42 0d [2] 69 21 [2] 47 03 [2] 53 18 [2] 5c 02 [2] 42 1f [2] 40 1e [2] 5b 18 [2] 47 1f [2] 5b 30 }

  condition:
    any of them
}