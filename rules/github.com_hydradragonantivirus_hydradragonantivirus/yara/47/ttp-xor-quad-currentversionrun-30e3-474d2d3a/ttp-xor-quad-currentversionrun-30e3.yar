rule TTP_XOR_QUAD_CurrentVersionRun_30e3 {
  strings:
    $key_30e3 = { 63 8c [2] 47 82 [2] 6c ae [2] 42 8c [2] 56 97 [2] 59 8d [2] 47 90 [2] 45 91 [2] 5e 97 [2] 42 90 [2] 5e bf }

  condition:
    any of them
}