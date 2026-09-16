rule TTP_XOR_QUAD_CurrentVersionRun_1327 {
  strings:
    $key_1327 = { 40 48 [2] 64 46 [2] 4f 6a [2] 61 48 [2] 75 53 [2] 7a 49 [2] 64 54 [2] 66 55 [2] 7d 53 [2] 61 54 [2] 7d 7b }

  condition:
    any of them
}