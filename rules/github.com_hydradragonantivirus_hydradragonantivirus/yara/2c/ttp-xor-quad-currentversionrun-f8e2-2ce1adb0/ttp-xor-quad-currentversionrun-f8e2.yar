rule TTP_XOR_QUAD_CurrentVersionRun_f8e2 {
  strings:
    $key_f8e2 = { ab 8d [2] 8f 83 [2] a4 af [2] 8a 8d [2] 9e 96 [2] 91 8c [2] 8f 91 [2] 8d 90 [2] 96 96 [2] 8a 91 [2] 96 be }

  condition:
    any of them
}