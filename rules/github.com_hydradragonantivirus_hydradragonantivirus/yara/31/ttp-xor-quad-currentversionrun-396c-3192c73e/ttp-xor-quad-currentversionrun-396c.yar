rule TTP_XOR_QUAD_CurrentVersionRun_396c {
  strings:
    $key_396c = { 6a 03 [2] 4e 0d [2] 65 21 [2] 4b 03 [2] 5f 18 [2] 50 02 [2] 4e 1f [2] 4c 1e [2] 57 18 [2] 4b 1f [2] 57 30 }

  condition:
    any of them
}