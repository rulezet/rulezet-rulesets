rule TTP_XOR_QUAD_CurrentVersionRun_26e2 {
  strings:
    $key_26e2 = { 75 8d [2] 51 83 [2] 7a af [2] 54 8d [2] 40 96 [2] 4f 8c [2] 51 91 [2] 53 90 [2] 48 96 [2] 54 91 [2] 48 be }

  condition:
    any of them
}