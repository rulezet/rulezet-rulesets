rule TTP_XOR_QUAD_CurrentVersionRun_e84b {
  strings:
    $key_e84b = { bb 24 [2] 9f 2a [2] b4 06 [2] 9a 24 [2] 8e 3f [2] 81 25 [2] 9f 38 [2] 9d 39 [2] 86 3f [2] 9a 38 [2] 86 17 }

  condition:
    any of them
}