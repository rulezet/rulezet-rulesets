rule TTP_XOR_QUAD_CurrentVersionRun_683d {
  strings:
    $key_683d = { 3b 52 [2] 1f 5c [2] 34 70 [2] 1a 52 [2] 0e 49 [2] 01 53 [2] 1f 4e [2] 1d 4f [2] 06 49 [2] 1a 4e [2] 06 61 }

  condition:
    any of them
}