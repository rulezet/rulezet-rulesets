rule TTP_XOR_QUAD_CurrentVersionRun_e34b {
  strings:
    $key_e34b = { b0 24 [2] 94 2a [2] bf 06 [2] 91 24 [2] 85 3f [2] 8a 25 [2] 94 38 [2] 96 39 [2] 8d 3f [2] 91 38 [2] 8d 17 }

  condition:
    any of them
}