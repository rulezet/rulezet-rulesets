rule TTP_XOR_QUAD_CurrentVersionRun_ef2b {
  strings:
    $key_ef2b = { bc 44 [2] 98 4a [2] b3 66 [2] 9d 44 [2] 89 5f [2] 86 45 [2] 98 58 [2] 9a 59 [2] 81 5f [2] 9d 58 [2] 81 77 }

  condition:
    any of them
}