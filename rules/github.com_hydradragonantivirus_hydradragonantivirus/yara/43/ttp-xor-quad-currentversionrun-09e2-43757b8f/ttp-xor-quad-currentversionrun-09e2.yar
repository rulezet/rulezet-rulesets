rule TTP_XOR_QUAD_CurrentVersionRun_09e2 {
  strings:
    $key_09e2 = { 5a 8d [2] 7e 83 [2] 55 af [2] 7b 8d [2] 6f 96 [2] 60 8c [2] 7e 91 [2] 7c 90 [2] 67 96 [2] 7b 91 [2] 67 be }

  condition:
    any of them
}