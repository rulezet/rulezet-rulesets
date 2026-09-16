rule TTP_XOR_QUAD_CurrentVersionRun_02e2 {
  strings:
    $key_02e2 = { 51 8d [2] 75 83 [2] 5e af [2] 70 8d [2] 64 96 [2] 6b 8c [2] 75 91 [2] 77 90 [2] 6c 96 [2] 70 91 [2] 6c be }

  condition:
    any of them
}