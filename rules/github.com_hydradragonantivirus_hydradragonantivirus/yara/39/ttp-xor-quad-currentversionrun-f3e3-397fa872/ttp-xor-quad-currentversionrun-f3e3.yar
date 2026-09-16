rule TTP_XOR_QUAD_CurrentVersionRun_f3e3 {
  strings:
    $key_f3e3 = { a0 8c [2] 84 82 [2] af ae [2] 81 8c [2] 95 97 [2] 9a 8d [2] 84 90 [2] 86 91 [2] 9d 97 [2] 81 90 [2] 9d bf }

  condition:
    any of them
}