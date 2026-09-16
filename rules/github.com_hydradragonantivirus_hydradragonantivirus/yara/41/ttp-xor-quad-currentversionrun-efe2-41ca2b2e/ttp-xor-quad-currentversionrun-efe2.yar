rule TTP_XOR_QUAD_CurrentVersionRun_efe2 {
  strings:
    $key_efe2 = { bc 8d [2] 98 83 [2] b3 af [2] 9d 8d [2] 89 96 [2] 86 8c [2] 98 91 [2] 9a 90 [2] 81 96 [2] 9d 91 [2] 81 be }

  condition:
    any of them
}