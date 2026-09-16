rule TTP_XOR_QUAD_CurrentVersionRun_2071 {
  strings:
    $key_2071 = { 73 1e [2] 57 10 [2] 7c 3c [2] 52 1e [2] 46 05 [2] 49 1f [2] 57 02 [2] 55 03 [2] 4e 05 [2] 52 02 [2] 4e 2d }

  condition:
    any of them
}