rule TTP_XOR_QUAD_CurrentVersionRun_33e2 {
  strings:
    $key_33e2 = { 60 8d [2] 44 83 [2] 6f af [2] 41 8d [2] 55 96 [2] 5a 8c [2] 44 91 [2] 46 90 [2] 5d 96 [2] 41 91 [2] 5d be }

  condition:
    any of them
}