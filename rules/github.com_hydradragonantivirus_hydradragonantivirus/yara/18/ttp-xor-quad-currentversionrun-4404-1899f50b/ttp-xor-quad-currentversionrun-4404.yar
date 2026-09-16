rule TTP_XOR_QUAD_CurrentVersionRun_4404 {
  strings:
    $key_4404 = { 17 6b [2] 33 65 [2] 18 49 [2] 36 6b [2] 22 70 [2] 2d 6a [2] 33 77 [2] 31 76 [2] 2a 70 [2] 36 77 [2] 2a 58 }

  condition:
    any of them
}