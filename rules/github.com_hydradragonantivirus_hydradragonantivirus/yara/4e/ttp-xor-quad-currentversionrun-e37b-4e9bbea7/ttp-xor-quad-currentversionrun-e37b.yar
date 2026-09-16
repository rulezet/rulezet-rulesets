rule TTP_XOR_QUAD_CurrentVersionRun_e37b {
  strings:
    $key_e37b = { b0 14 [2] 94 1a [2] bf 36 [2] 91 14 [2] 85 0f [2] 8a 15 [2] 94 08 [2] 96 09 [2] 8d 0f [2] 91 08 [2] 8d 27 }

  condition:
    any of them
}