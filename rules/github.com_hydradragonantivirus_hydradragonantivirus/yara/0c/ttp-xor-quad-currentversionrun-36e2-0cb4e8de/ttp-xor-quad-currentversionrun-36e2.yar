rule TTP_XOR_QUAD_CurrentVersionRun_36e2 {
  strings:
    $key_36e2 = { 65 8d [2] 41 83 [2] 6a af [2] 44 8d [2] 50 96 [2] 5f 8c [2] 41 91 [2] 43 90 [2] 58 96 [2] 44 91 [2] 58 be }

  condition:
    any of them
}