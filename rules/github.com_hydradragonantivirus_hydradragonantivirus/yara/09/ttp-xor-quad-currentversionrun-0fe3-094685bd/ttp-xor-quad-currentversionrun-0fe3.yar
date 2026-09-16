rule TTP_XOR_QUAD_CurrentVersionRun_0fe3 {
  strings:
    $key_0fe3 = { 5c 8c [2] 78 82 [2] 53 ae [2] 7d 8c [2] 69 97 [2] 66 8d [2] 78 90 [2] 7a 91 [2] 61 97 [2] 7d 90 [2] 61 bf }

  condition:
    any of them
}