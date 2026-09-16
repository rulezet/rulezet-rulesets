rule TTP_XOR_QUAD_CurrentVersionRun_3b6d {
  strings:
    $key_3b6d = { 68 02 [2] 4c 0c [2] 67 20 [2] 49 02 [2] 5d 19 [2] 52 03 [2] 4c 1e [2] 4e 1f [2] 55 19 [2] 49 1e [2] 55 31 }

  condition:
    any of them
}