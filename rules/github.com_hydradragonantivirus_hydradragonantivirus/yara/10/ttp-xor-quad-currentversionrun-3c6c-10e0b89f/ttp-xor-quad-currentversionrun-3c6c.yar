rule TTP_XOR_QUAD_CurrentVersionRun_3c6c {
  strings:
    $key_3c6c = { 6f 03 [2] 4b 0d [2] 60 21 [2] 4e 03 [2] 5a 18 [2] 55 02 [2] 4b 1f [2] 49 1e [2] 52 18 [2] 4e 1f [2] 52 30 }

  condition:
    any of them
}