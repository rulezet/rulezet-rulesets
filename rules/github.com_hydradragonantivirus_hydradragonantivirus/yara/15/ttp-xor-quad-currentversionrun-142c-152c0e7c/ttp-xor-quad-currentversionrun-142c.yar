rule TTP_XOR_QUAD_CurrentVersionRun_142c {
  strings:
    $key_142c = { 47 43 [2] 63 4d [2] 48 61 [2] 66 43 [2] 72 58 [2] 7d 42 [2] 63 5f [2] 61 5e [2] 7a 58 [2] 66 5f [2] 7a 70 }

  condition:
    any of them
}