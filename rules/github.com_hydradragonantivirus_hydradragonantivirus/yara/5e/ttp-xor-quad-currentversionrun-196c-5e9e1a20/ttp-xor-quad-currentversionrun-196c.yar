rule TTP_XOR_QUAD_CurrentVersionRun_196c {
  strings:
    $key_196c = { 4a 03 [2] 6e 0d [2] 45 21 [2] 6b 03 [2] 7f 18 [2] 70 02 [2] 6e 1f [2] 6c 1e [2] 77 18 [2] 6b 1f [2] 77 30 }

  condition:
    any of them
}