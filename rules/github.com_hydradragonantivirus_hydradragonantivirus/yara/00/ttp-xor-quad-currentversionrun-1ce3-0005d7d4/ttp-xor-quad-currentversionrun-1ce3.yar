rule TTP_XOR_QUAD_CurrentVersionRun_1ce3 {
  strings:
    $key_1ce3 = { 4f 8c [2] 6b 82 [2] 40 ae [2] 6e 8c [2] 7a 97 [2] 75 8d [2] 6b 90 [2] 69 91 [2] 72 97 [2] 6e 90 [2] 72 bf }

  condition:
    any of them
}