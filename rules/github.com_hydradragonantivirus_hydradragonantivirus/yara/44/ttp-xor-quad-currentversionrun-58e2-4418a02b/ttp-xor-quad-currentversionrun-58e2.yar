rule TTP_XOR_QUAD_CurrentVersionRun_58e2 {
  strings:
    $key_58e2 = { 0b 8d [2] 2f 83 [2] 04 af [2] 2a 8d [2] 3e 96 [2] 31 8c [2] 2f 91 [2] 2d 90 [2] 36 96 [2] 2a 91 [2] 36 be }

  condition:
    any of them
}