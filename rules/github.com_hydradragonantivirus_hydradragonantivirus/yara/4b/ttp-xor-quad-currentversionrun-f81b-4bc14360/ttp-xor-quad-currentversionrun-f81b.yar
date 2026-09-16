rule TTP_XOR_QUAD_CurrentVersionRun_f81b {
  strings:
    $key_f81b = { ab 74 [2] 8f 7a [2] a4 56 [2] 8a 74 [2] 9e 6f [2] 91 75 [2] 8f 68 [2] 8d 69 [2] 96 6f [2] 8a 68 [2] 96 47 }

  condition:
    any of them
}