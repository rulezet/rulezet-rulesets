rule TTP_XOR_QUAD_CurrentVersionRun_30e2 {
  strings:
    $key_30e2 = { 63 8d [2] 47 83 [2] 6c af [2] 42 8d [2] 56 96 [2] 59 8c [2] 47 91 [2] 45 90 [2] 5e 96 [2] 42 91 [2] 5e be }

  condition:
    any of them
}