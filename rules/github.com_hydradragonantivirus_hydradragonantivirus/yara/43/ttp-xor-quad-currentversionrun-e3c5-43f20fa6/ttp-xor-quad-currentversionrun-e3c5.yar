rule TTP_XOR_QUAD_CurrentVersionRun_e3c5 {
  strings:
    $key_e3c5 = { b0 aa [2] 94 a4 [2] bf 88 [2] 91 aa [2] 85 b1 [2] 8a ab [2] 94 b6 [2] 96 b7 [2] 8d b1 [2] 91 b6 [2] 8d 99 }

  condition:
    any of them
}