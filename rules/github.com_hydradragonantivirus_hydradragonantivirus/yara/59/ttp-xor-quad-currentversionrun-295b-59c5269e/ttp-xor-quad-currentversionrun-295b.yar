rule TTP_XOR_QUAD_CurrentVersionRun_295b {
  strings:
    $key_295b = { 7a 34 [2] 5e 3a [2] 75 16 [2] 5b 34 [2] 4f 2f [2] 40 35 [2] 5e 28 [2] 5c 29 [2] 47 2f [2] 5b 28 [2] 47 07 }

  condition:
    any of them
}