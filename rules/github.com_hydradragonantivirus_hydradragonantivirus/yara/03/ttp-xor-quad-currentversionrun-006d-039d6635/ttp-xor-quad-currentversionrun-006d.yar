rule TTP_XOR_QUAD_CurrentVersionRun_006d {
  strings:
    $key_006d = { 53 02 [2] 77 0c [2] 5c 20 [2] 72 02 [2] 66 19 [2] 69 03 [2] 77 1e [2] 75 1f [2] 6e 19 [2] 72 1e [2] 6e 31 }

  condition:
    any of them
}