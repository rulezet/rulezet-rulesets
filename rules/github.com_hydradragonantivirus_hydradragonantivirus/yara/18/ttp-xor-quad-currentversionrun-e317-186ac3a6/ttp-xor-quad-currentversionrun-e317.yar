rule TTP_XOR_QUAD_CurrentVersionRun_e317 {
  strings:
    $key_e317 = { b0 78 [2] 94 76 [2] bf 5a [2] 91 78 [2] 85 63 [2] 8a 79 [2] 94 64 [2] 96 65 [2] 8d 63 [2] 91 64 [2] 8d 4b }

  condition:
    any of them
}