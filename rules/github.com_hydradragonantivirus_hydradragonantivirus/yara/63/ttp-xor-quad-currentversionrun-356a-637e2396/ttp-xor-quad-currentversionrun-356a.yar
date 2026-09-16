rule TTP_XOR_QUAD_CurrentVersionRun_356a {
  strings:
    $key_356a = { 66 05 [2] 42 0b [2] 69 27 [2] 47 05 [2] 53 1e [2] 5c 04 [2] 42 19 [2] 40 18 [2] 5b 1e [2] 47 19 [2] 5b 36 }

  condition:
    any of them
}