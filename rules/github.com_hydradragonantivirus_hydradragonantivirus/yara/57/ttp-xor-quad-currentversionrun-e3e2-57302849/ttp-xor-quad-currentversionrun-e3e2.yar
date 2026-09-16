rule TTP_XOR_QUAD_CurrentVersionRun_e3e2 {
  strings:
    $key_e3e2 = { b0 8d [2] 94 83 [2] bf af [2] 91 8d [2] 85 96 [2] 8a 8c [2] 94 91 [2] 96 90 [2] 8d 96 [2] 91 91 [2] 8d be }

  condition:
    any of them
}