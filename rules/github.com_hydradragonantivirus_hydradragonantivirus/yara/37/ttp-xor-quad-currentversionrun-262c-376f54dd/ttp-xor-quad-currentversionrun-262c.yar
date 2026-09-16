rule TTP_XOR_QUAD_CurrentVersionRun_262c {
  strings:
    $key_262c = { 75 43 [2] 51 4d [2] 7a 61 [2] 54 43 [2] 40 58 [2] 4f 42 [2] 51 5f [2] 53 5e [2] 48 58 [2] 54 5f [2] 48 70 }

  condition:
    any of them
}