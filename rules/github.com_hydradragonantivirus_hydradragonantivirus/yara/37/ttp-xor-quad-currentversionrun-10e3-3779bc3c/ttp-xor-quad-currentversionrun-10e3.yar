rule TTP_XOR_QUAD_CurrentVersionRun_10e3 {
  strings:
    $key_10e3 = { 43 8c [2] 67 82 [2] 4c ae [2] 62 8c [2] 76 97 [2] 79 8d [2] 67 90 [2] 65 91 [2] 7e 97 [2] 62 90 [2] 7e bf }

  condition:
    any of them
}