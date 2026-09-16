rule TTP_XOR_QUAD_CurrentVersionRun_e327 {
  strings:
    $key_e327 = { b0 48 [2] 94 46 [2] bf 6a [2] 91 48 [2] 85 53 [2] 8a 49 [2] 94 54 [2] 96 55 [2] 8d 53 [2] 91 54 [2] 8d 7b }

  condition:
    any of them
}