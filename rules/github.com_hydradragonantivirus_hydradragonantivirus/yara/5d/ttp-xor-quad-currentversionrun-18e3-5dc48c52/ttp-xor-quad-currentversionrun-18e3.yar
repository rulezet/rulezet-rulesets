rule TTP_XOR_QUAD_CurrentVersionRun_18e3 {
  strings:
    $key_18e3 = { 4b 8c [2] 6f 82 [2] 44 ae [2] 6a 8c [2] 7e 97 [2] 71 8d [2] 6f 90 [2] 6d 91 [2] 76 97 [2] 6a 90 [2] 76 bf }

  condition:
    any of them
}