rule TTP_XOR_QUAD_CurrentVersionRun_e0e3 {
  strings:
    $key_e0e3 = { b3 8c [2] 97 82 [2] bc ae [2] 92 8c [2] 86 97 [2] 89 8d [2] 97 90 [2] 95 91 [2] 8e 97 [2] 92 90 [2] 8e bf }

  condition:
    any of them
}