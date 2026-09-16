rule TTP_XOR_QUAD_CurrentVersionRun_f83b {
  strings:
    $key_f83b = { ab 54 [2] 8f 5a [2] a4 76 [2] 8a 54 [2] 9e 4f [2] 91 55 [2] 8f 48 [2] 8d 49 [2] 96 4f [2] 8a 48 [2] 96 67 }

  condition:
    any of them
}