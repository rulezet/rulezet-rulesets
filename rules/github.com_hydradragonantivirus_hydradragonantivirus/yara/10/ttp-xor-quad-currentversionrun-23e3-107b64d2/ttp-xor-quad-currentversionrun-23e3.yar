rule TTP_XOR_QUAD_CurrentVersionRun_23e3 {
  strings:
    $key_23e3 = { 70 8c [2] 54 82 [2] 7f ae [2] 51 8c [2] 45 97 [2] 4a 8d [2] 54 90 [2] 56 91 [2] 4d 97 [2] 51 90 [2] 4d bf }

  condition:
    any of them
}