rule TTP_XOR_QUAD_CurrentVersionRun_f7e2 {
  strings:
    $key_f7e2 = { a4 8d [2] 80 83 [2] ab af [2] 85 8d [2] 91 96 [2] 9e 8c [2] 80 91 [2] 82 90 [2] 99 96 [2] 85 91 [2] 99 be }

  condition:
    any of them
}