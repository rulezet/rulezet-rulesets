rule TTP_XOR_QUAD_CurrentVersionRun_e3e5 {
  strings:
    $key_e3e5 = { b0 8a [2] 94 84 [2] bf a8 [2] 91 8a [2] 85 91 [2] 8a 8b [2] 94 96 [2] 96 97 [2] 8d 91 [2] 91 96 [2] 8d b9 }

  condition:
    any of them
}