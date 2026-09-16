rule TTP_XOR_QUAD_CurrentVersionRun_5355 {
  strings:
    $key_5355 = { 00 3a [2] 24 34 [2] 0f 18 [2] 21 3a [2] 35 21 [2] 3a 3b [2] 24 26 [2] 26 27 [2] 3d 21 [2] 21 26 [2] 3d 09 }

  condition:
    any of them
}