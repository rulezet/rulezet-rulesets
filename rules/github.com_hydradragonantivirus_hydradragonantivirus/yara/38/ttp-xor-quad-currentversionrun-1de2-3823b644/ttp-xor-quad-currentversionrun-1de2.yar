rule TTP_XOR_QUAD_CurrentVersionRun_1de2 {
  strings:
    $key_1de2 = { 4e 8d [2] 6a 83 [2] 41 af [2] 6f 8d [2] 7b 96 [2] 74 8c [2] 6a 91 [2] 68 90 [2] 73 96 [2] 6f 91 [2] 73 be }

  condition:
    any of them
}