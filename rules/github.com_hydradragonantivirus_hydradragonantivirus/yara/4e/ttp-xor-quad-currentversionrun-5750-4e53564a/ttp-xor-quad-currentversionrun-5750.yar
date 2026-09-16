rule TTP_XOR_QUAD_CurrentVersionRun_5750 {
  strings:
    $key_5750 = { 04 3f [2] 20 31 [2] 0b 1d [2] 25 3f [2] 31 24 [2] 3e 3e [2] 20 23 [2] 22 22 [2] 39 24 [2] 25 23 [2] 39 0c }

  condition:
    any of them
}