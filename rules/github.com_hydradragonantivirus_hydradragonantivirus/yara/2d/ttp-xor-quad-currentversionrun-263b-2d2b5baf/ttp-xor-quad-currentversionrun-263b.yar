rule TTP_XOR_QUAD_CurrentVersionRun_263b {
  strings:
    $key_263b = { 75 54 [2] 51 5a [2] 7a 76 [2] 54 54 [2] 40 4f [2] 4f 55 [2] 51 48 [2] 53 49 [2] 48 4f [2] 54 48 [2] 48 67 }

  condition:
    any of them
}