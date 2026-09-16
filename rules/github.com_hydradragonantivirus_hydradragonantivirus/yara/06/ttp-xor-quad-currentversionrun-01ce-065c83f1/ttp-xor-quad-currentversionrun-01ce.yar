rule TTP_XOR_QUAD_CurrentVersionRun_01ce {
  strings:
    $key_01ce = { 52 a1 [2] 76 af [2] 5d 83 [2] 73 a1 [2] 67 ba [2] 68 a0 [2] 76 bd [2] 74 bc [2] 6f ba [2] 73 bd [2] 6f 92 }

  condition:
    any of them
}