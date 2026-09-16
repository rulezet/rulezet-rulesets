rule TTP_XOR_QUAD_CurrentVersionRun_3ae2 {
  strings:
    $key_3ae2 = { 69 8d [2] 4d 83 [2] 66 af [2] 48 8d [2] 5c 96 [2] 53 8c [2] 4d 91 [2] 4f 90 [2] 54 96 [2] 48 91 [2] 54 be }

  condition:
    any of them
}