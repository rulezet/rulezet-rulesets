rule TTP_XOR_QUAD_CurrentVersionRun_13e3 {
  strings:
    $key_13e3 = { 40 8c [2] 64 82 [2] 4f ae [2] 61 8c [2] 75 97 [2] 7a 8d [2] 64 90 [2] 66 91 [2] 7d 97 [2] 61 90 [2] 7d bf }

  condition:
    any of them
}