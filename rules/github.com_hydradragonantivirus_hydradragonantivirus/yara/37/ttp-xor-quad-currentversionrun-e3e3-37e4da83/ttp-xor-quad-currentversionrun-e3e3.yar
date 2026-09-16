rule TTP_XOR_QUAD_CurrentVersionRun_e3e3 {
  strings:
    $key_e3e3 = { b0 8c [2] 94 82 [2] bf ae [2] 91 8c [2] 85 97 [2] 8a 8d [2] 94 90 [2] 96 91 [2] 8d 97 [2] 91 90 [2] 8d bf }

  condition:
    any of them
}