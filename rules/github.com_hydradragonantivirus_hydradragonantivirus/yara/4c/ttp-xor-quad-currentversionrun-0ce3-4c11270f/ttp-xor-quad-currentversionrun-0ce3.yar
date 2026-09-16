rule TTP_XOR_QUAD_CurrentVersionRun_0ce3 {
  strings:
    $key_0ce3 = { 5f 8c [2] 7b 82 [2] 50 ae [2] 7e 8c [2] 6a 97 [2] 65 8d [2] 7b 90 [2] 79 91 [2] 62 97 [2] 7e 90 [2] 62 bf }

  condition:
    any of them
}