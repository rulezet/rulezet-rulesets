rule TTP_XOR_QUAD_CurrentVersionRun_73e2 {
  strings:
    $key_73e2 = { 20 8d [2] 04 83 [2] 2f af [2] 01 8d [2] 15 96 [2] 1a 8c [2] 04 91 [2] 06 90 [2] 1d 96 [2] 01 91 [2] 1d be }

  condition:
    any of them
}