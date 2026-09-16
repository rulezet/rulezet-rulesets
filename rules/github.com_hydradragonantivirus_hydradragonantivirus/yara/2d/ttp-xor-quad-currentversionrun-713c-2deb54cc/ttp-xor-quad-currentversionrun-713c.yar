rule TTP_XOR_QUAD_CurrentVersionRun_713c {
  strings:
    $key_713c = { 22 53 [2] 06 5d [2] 2d 71 [2] 03 53 [2] 17 48 [2] 18 52 [2] 06 4f [2] 04 4e [2] 1f 48 [2] 03 4f [2] 1f 60 }

  condition:
    any of them
}