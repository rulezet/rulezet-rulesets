rule TTP_XOR_QUAD_CurrentVersionRun_056c {
  strings:
    $key_056c = { 56 03 [2] 72 0d [2] 59 21 [2] 77 03 [2] 63 18 [2] 6c 02 [2] 72 1f [2] 70 1e [2] 6b 18 [2] 77 1f [2] 6b 30 }

  condition:
    any of them
}