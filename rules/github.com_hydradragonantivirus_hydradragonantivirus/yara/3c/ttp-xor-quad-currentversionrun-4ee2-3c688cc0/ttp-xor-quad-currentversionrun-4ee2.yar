rule TTP_XOR_QUAD_CurrentVersionRun_4ee2 {
  strings:
    $key_4ee2 = { 1d 8d [2] 39 83 [2] 12 af [2] 3c 8d [2] 28 96 [2] 27 8c [2] 39 91 [2] 3b 90 [2] 20 96 [2] 3c 91 [2] 20 be }

  condition:
    any of them
}