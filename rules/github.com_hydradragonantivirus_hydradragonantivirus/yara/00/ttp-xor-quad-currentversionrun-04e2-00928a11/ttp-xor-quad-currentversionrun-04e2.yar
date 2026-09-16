rule TTP_XOR_QUAD_CurrentVersionRun_04e2 {
  strings:
    $key_04e2 = { 57 8d [2] 73 83 [2] 58 af [2] 76 8d [2] 62 96 [2] 6d 8c [2] 73 91 [2] 71 90 [2] 6a 96 [2] 76 91 [2] 6a be }

  condition:
    any of them
}