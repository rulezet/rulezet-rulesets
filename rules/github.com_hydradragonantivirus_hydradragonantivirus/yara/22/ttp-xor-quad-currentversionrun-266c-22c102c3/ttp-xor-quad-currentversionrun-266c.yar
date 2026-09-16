rule TTP_XOR_QUAD_CurrentVersionRun_266c {
  strings:
    $key_266c = { 75 03 [2] 51 0d [2] 7a 21 [2] 54 03 [2] 40 18 [2] 4f 02 [2] 51 1f [2] 53 1e [2] 48 18 [2] 54 1f [2] 48 30 }

  condition:
    any of them
}