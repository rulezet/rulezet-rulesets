rule TTP_XOR_QUAD_CurrentVersionRun_e417 {
  strings:
    $key_e417 = { b7 78 [2] 93 76 [2] b8 5a [2] 96 78 [2] 82 63 [2] 8d 79 [2] 93 64 [2] 91 65 [2] 8a 63 [2] 96 64 [2] 8a 4b }

  condition:
    any of them
}