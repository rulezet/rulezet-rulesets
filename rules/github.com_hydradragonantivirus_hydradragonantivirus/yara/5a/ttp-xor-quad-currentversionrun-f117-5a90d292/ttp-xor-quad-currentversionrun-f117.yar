rule TTP_XOR_QUAD_CurrentVersionRun_f117 {
  strings:
    $key_f117 = { a2 78 [2] 86 76 [2] ad 5a [2] 83 78 [2] 97 63 [2] 98 79 [2] 86 64 [2] 84 65 [2] 9f 63 [2] 83 64 [2] 9f 4b }

  condition:
    any of them
}