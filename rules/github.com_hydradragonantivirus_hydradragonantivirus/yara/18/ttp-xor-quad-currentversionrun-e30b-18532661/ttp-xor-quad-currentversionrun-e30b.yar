rule TTP_XOR_QUAD_CurrentVersionRun_e30b {
  strings:
    $key_e30b = { b0 64 [2] 94 6a [2] bf 46 [2] 91 64 [2] 85 7f [2] 8a 65 [2] 94 78 [2] 96 79 [2] 8d 7f [2] 91 78 [2] 8d 57 }

  condition:
    any of them
}