rule TTP_XOR_QUAD_CurrentVersionRun_22e2 {
  strings:
    $key_22e2 = { 71 8d [2] 55 83 [2] 7e af [2] 50 8d [2] 44 96 [2] 4b 8c [2] 55 91 [2] 57 90 [2] 4c 96 [2] 50 91 [2] 4c be }

  condition:
    any of them
}