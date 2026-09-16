rule TTP_XOR_QUAD_CurrentVersionRun_f11b {
  strings:
    $key_f11b = { a2 74 [2] 86 7a [2] ad 56 [2] 83 74 [2] 97 6f [2] 98 75 [2] 86 68 [2] 84 69 [2] 9f 6f [2] 83 68 [2] 9f 47 }

  condition:
    any of them
}