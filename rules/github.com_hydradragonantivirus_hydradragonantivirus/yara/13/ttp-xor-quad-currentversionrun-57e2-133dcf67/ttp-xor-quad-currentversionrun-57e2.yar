rule TTP_XOR_QUAD_CurrentVersionRun_57e2 {
  strings:
    $key_57e2 = { 04 8d [2] 20 83 [2] 0b af [2] 25 8d [2] 31 96 [2] 3e 8c [2] 20 91 [2] 22 90 [2] 39 96 [2] 25 91 [2] 39 be }

  condition:
    any of them
}