rule TTP_XOR_QUAD_CurrentVersionRun_55e3 {
  strings:
    $key_55e3 = { 06 8c [2] 22 82 [2] 09 ae [2] 27 8c [2] 33 97 [2] 3c 8d [2] 22 90 [2] 20 91 [2] 3b 97 [2] 27 90 [2] 3b bf }

  condition:
    any of them
}