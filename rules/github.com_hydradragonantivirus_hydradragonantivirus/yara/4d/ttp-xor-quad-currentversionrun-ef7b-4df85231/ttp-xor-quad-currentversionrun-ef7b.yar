rule TTP_XOR_QUAD_CurrentVersionRun_ef7b {
  strings:
    $key_ef7b = { bc 14 [2] 98 1a [2] b3 36 [2] 9d 14 [2] 89 0f [2] 86 15 [2] 98 08 [2] 9a 09 [2] 81 0f [2] 9d 08 [2] 81 27 }

  condition:
    any of them
}