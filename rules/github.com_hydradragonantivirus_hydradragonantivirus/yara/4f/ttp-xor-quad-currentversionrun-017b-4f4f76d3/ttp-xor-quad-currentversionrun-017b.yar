rule TTP_XOR_QUAD_CurrentVersionRun_017b {
  strings:
    $key_017b = { 52 14 [2] 76 1a [2] 5d 36 [2] 73 14 [2] 67 0f [2] 68 15 [2] 76 08 [2] 74 09 [2] 6f 0f [2] 73 08 [2] 6f 27 }

  condition:
    any of them
}