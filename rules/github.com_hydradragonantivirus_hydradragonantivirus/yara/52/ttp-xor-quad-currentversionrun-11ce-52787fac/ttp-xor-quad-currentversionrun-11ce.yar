rule TTP_XOR_QUAD_CurrentVersionRun_11ce {
  strings:
    $key_11ce = { 42 a1 [2] 66 af [2] 4d 83 [2] 63 a1 [2] 77 ba [2] 78 a0 [2] 66 bd [2] 64 bc [2] 7f ba [2] 63 bd [2] 7f 92 }

  condition:
    any of them
}