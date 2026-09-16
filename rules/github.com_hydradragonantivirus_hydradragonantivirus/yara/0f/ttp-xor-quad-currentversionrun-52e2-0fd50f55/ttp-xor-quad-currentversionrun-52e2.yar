rule TTP_XOR_QUAD_CurrentVersionRun_52e2 {
  strings:
    $key_52e2 = { 01 8d [2] 25 83 [2] 0e af [2] 20 8d [2] 34 96 [2] 3b 8c [2] 25 91 [2] 27 90 [2] 3c 96 [2] 20 91 [2] 3c be }

  condition:
    any of them
}