rule TTP_XOR_QUAD_CurrentVersionRun_53e3 {
  strings:
    $key_53e3 = { 00 8c [2] 24 82 [2] 0f ae [2] 21 8c [2] 35 97 [2] 3a 8d [2] 24 90 [2] 26 91 [2] 3d 97 [2] 21 90 [2] 3d bf }

  condition:
    any of them
}