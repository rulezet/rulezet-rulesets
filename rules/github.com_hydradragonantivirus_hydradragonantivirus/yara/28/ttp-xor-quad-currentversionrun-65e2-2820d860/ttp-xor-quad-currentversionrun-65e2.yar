rule TTP_XOR_QUAD_CurrentVersionRun_65e2 {
  strings:
    $key_65e2 = { 36 8d [2] 12 83 [2] 39 af [2] 17 8d [2] 03 96 [2] 0c 8c [2] 12 91 [2] 10 90 [2] 0b 96 [2] 17 91 [2] 0b be }

  condition:
    any of them
}