rule TTP_XOR_QUAD_CurrentVersionRun_01e2 {
  strings:
    $key_01e2 = { 52 8d [2] 76 83 [2] 5d af [2] 73 8d [2] 67 96 [2] 68 8c [2] 76 91 [2] 74 90 [2] 6f 96 [2] 73 91 [2] 6f be }

  condition:
    any of them
}