rule TTP_XOR_QUAD_CurrentVersionRun_2e6d {
  strings:
    $key_2e6d = { 7d 02 [2] 59 0c [2] 72 20 [2] 5c 02 [2] 48 19 [2] 47 03 [2] 59 1e [2] 5b 1f [2] 40 19 [2] 5c 1e [2] 40 31 }

  condition:
    any of them
}