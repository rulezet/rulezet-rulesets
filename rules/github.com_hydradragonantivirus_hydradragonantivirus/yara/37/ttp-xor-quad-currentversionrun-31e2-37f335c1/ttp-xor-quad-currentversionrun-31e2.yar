rule TTP_XOR_QUAD_CurrentVersionRun_31e2 {
  strings:
    $key_31e2 = { 62 8d [2] 46 83 [2] 6d af [2] 43 8d [2] 57 96 [2] 58 8c [2] 46 91 [2] 44 90 [2] 5f 96 [2] 43 91 [2] 5f be }

  condition:
    any of them
}