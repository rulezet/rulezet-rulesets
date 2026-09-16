rule TTP_XOR_QUAD_CurrentVersionRun_5071 {
  strings:
    $key_5071 = { 03 1e [2] 27 10 [2] 0c 3c [2] 22 1e [2] 36 05 [2] 39 1f [2] 27 02 [2] 25 03 [2] 3e 05 [2] 22 02 [2] 3e 2d }

  condition:
    any of them
}