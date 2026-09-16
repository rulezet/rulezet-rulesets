rule TTP_XOR_QUAD_CurrentVersionRun_52e3 {
  strings:
    $key_52e3 = { 01 8c [2] 25 82 [2] 0e ae [2] 20 8c [2] 34 97 [2] 3b 8d [2] 25 90 [2] 27 91 [2] 3c 97 [2] 20 90 [2] 3c bf }

  condition:
    any of them
}