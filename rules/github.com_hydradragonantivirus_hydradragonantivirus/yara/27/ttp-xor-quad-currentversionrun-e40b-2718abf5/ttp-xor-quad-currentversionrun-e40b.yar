rule TTP_XOR_QUAD_CurrentVersionRun_e40b {
  strings:
    $key_e40b = { b7 64 [2] 93 6a [2] b8 46 [2] 96 64 [2] 82 7f [2] 8d 65 [2] 93 78 [2] 91 79 [2] 8a 7f [2] 96 78 [2] 8a 57 }

  condition:
    any of them
}