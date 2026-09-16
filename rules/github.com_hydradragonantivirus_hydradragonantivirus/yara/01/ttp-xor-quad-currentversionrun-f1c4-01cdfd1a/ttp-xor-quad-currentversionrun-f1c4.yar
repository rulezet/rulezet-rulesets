rule TTP_XOR_QUAD_CurrentVersionRun_f1c4 {
  strings:
    $key_f1c4 = { a2 ab [2] 86 a5 [2] ad 89 [2] 83 ab [2] 97 b0 [2] 98 aa [2] 86 b7 [2] 84 b6 [2] 9f b0 [2] 83 b7 [2] 9f 98 }

  condition:
    any of them
}