rule TTP_XOR_QUAD_CurrentVersionRun_2fe3 {
  strings:
    $key_2fe3 = { 7c 8c [2] 58 82 [2] 73 ae [2] 5d 8c [2] 49 97 [2] 46 8d [2] 58 90 [2] 5a 91 [2] 41 97 [2] 5d 90 [2] 41 bf }

  condition:
    any of them
}