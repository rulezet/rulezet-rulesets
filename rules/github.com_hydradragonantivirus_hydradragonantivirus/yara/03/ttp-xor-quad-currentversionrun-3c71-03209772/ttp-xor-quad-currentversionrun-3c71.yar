rule TTP_XOR_QUAD_CurrentVersionRun_3c71 {
  strings:
    $key_3c71 = { 6f 1e [2] 4b 10 [2] 60 3c [2] 4e 1e [2] 5a 05 [2] 55 1f [2] 4b 02 [2] 49 03 [2] 52 05 [2] 4e 02 [2] 52 2d }

  condition:
    any of them
}