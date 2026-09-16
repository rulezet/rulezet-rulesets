rule TTP_XOR_QUAD_CurrentVersionRun_3ce2 {
  strings:
    $key_3ce2 = { 6f 8d [2] 4b 83 [2] 60 af [2] 4e 8d [2] 5a 96 [2] 55 8c [2] 4b 91 [2] 49 90 [2] 52 96 [2] 4e 91 [2] 52 be }

  condition:
    any of them
}