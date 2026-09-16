rule TTP_XOR_QUAD_CurrentVersionRun_266d {
  strings:
    $key_266d = { 75 02 [2] 51 0c [2] 7a 20 [2] 54 02 [2] 40 19 [2] 4f 03 [2] 51 1e [2] 53 1f [2] 48 19 [2] 54 1e [2] 48 31 }

  condition:
    any of them
}