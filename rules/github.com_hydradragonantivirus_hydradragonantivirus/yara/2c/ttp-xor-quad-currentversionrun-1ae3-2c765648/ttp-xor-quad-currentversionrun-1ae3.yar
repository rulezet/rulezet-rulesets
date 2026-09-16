rule TTP_XOR_QUAD_CurrentVersionRun_1ae3 {
  strings:
    $key_1ae3 = { 49 8c [2] 6d 82 [2] 46 ae [2] 68 8c [2] 7c 97 [2] 73 8d [2] 6d 90 [2] 6f 91 [2] 74 97 [2] 68 90 [2] 74 bf }

  condition:
    any of them
}