rule TTP_XOR_QUAD_CurrentVersionRun_62ce {
  strings:
    $key_62ce = { 31 a1 [2] 15 af [2] 3e 83 [2] 10 a1 [2] 04 ba [2] 0b a0 [2] 15 bd [2] 17 bc [2] 0c ba [2] 10 bd [2] 0c 92 }

  condition:
    any of them
}