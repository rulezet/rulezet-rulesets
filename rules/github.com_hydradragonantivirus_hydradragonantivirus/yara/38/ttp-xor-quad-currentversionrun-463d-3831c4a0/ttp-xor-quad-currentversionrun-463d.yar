rule TTP_XOR_QUAD_CurrentVersionRun_463d {
  strings:
    $key_463d = { 15 52 [2] 31 5c [2] 1a 70 [2] 34 52 [2] 20 49 [2] 2f 53 [2] 31 4e [2] 33 4f [2] 28 49 [2] 34 4e [2] 28 61 }

  condition:
    any of them
}