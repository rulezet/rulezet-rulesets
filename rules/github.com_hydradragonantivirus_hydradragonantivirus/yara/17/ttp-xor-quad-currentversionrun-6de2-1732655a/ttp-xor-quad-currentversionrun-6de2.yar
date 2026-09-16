rule TTP_XOR_QUAD_CurrentVersionRun_6de2 {
  strings:
    $key_6de2 = { 3e 8d [2] 1a 83 [2] 31 af [2] 1f 8d [2] 0b 96 [2] 04 8c [2] 1a 91 [2] 18 90 [2] 03 96 [2] 1f 91 [2] 03 be }

  condition:
    any of them
}