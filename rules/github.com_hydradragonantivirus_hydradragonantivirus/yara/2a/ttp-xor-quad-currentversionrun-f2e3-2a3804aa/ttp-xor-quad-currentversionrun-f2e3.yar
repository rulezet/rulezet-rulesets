rule TTP_XOR_QUAD_CurrentVersionRun_f2e3 {
  strings:
    $key_f2e3 = { a1 8c [2] 85 82 [2] ae ae [2] 80 8c [2] 94 97 [2] 9b 8d [2] 85 90 [2] 87 91 [2] 9c 97 [2] 80 90 [2] 9c bf }

  condition:
    any of them
}