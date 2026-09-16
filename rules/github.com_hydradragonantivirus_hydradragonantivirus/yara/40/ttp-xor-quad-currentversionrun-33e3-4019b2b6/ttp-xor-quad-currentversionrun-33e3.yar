rule TTP_XOR_QUAD_CurrentVersionRun_33e3 {
  strings:
    $key_33e3 = { 60 8c [2] 44 82 [2] 6f ae [2] 41 8c [2] 55 97 [2] 5a 8d [2] 44 90 [2] 46 91 [2] 5d 97 [2] 41 90 [2] 5d bf }

  condition:
    any of them
}