rule TTP_XOR_QUAD_CurrentVersionRun_03e3 {
  strings:
    $key_03e3 = { 50 8c [2] 74 82 [2] 5f ae [2] 71 8c [2] 65 97 [2] 6a 8d [2] 74 90 [2] 76 91 [2] 6d 97 [2] 71 90 [2] 6d bf }

  condition:
    any of them
}