rule TTP_XOR_QUAD_CurrentVersionRun_267b {
  strings:
    $key_267b = { 75 14 [2] 51 1a [2] 7a 36 [2] 54 14 [2] 40 0f [2] 4f 15 [2] 51 08 [2] 53 09 [2] 48 0f [2] 54 08 [2] 48 27 }

  condition:
    any of them
}