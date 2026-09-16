rule TTP_XOR_QUAD_CurrentVersionRun_713d {
  strings:
    $key_713d = { 22 52 [2] 06 5c [2] 2d 70 [2] 03 52 [2] 17 49 [2] 18 53 [2] 06 4e [2] 04 4f [2] 1f 49 [2] 03 4e [2] 1f 61 }

  condition:
    any of them
}