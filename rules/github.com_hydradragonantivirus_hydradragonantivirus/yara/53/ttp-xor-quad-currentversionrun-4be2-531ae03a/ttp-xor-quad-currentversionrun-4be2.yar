rule TTP_XOR_QUAD_CurrentVersionRun_4be2 {
  strings:
    $key_4be2 = { 18 8d [2] 3c 83 [2] 17 af [2] 39 8d [2] 2d 96 [2] 22 8c [2] 3c 91 [2] 3e 90 [2] 25 96 [2] 39 91 [2] 25 be }

  condition:
    any of them
}