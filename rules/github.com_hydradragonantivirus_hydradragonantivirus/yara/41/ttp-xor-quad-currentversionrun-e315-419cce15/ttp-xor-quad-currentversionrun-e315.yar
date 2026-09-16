rule TTP_XOR_QUAD_CurrentVersionRun_e315 {
  strings:
    $key_e315 = { b0 7a [2] 94 74 [2] bf 58 [2] 91 7a [2] 85 61 [2] 8a 7b [2] 94 66 [2] 96 67 [2] 8d 61 [2] 91 66 [2] 8d 49 }

  condition:
    any of them
}