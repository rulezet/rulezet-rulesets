rule TTP_XOR_QUAD_CurrentVersionRun_3420 {
  strings:
    $key_3420 = { 67 4f [2] 43 41 [2] 68 6d [2] 46 4f [2] 52 54 [2] 5d 4e [2] 43 53 [2] 41 52 [2] 5a 54 [2] 46 53 [2] 5a 7c }

  condition:
    any of them
}