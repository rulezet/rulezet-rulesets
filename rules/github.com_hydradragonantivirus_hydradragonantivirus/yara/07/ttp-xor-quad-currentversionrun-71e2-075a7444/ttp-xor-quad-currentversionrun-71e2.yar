rule TTP_XOR_QUAD_CurrentVersionRun_71e2 {
  strings:
    $key_71e2 = { 22 8d [2] 06 83 [2] 2d af [2] 03 8d [2] 17 96 [2] 18 8c [2] 06 91 [2] 04 90 [2] 1f 96 [2] 03 91 [2] 1f be }

  condition:
    any of them
}