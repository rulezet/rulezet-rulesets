rule TTP_XOR_QUAD_CurrentVersionRun_1b6d {
  strings:
    $key_1b6d = { 48 02 [2] 6c 0c [2] 47 20 [2] 69 02 [2] 7d 19 [2] 72 03 [2] 6c 1e [2] 6e 1f [2] 75 19 [2] 69 1e [2] 75 31 }

  condition:
    any of them
}