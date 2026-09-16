rule TTP_XOR_QUAD_CurrentVersionRun_ef3b {
  strings:
    $key_ef3b = { bc 54 [2] 98 5a [2] b3 76 [2] 9d 54 [2] 89 4f [2] 86 55 [2] 98 48 [2] 9a 49 [2] 81 4f [2] 9d 48 [2] 81 67 }

  condition:
    any of them
}