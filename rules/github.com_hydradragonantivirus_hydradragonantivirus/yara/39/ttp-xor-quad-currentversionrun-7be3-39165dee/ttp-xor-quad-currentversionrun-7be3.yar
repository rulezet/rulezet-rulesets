rule TTP_XOR_QUAD_CurrentVersionRun_7be3 {
  strings:
    $key_7be3 = { 28 8c [2] 0c 82 [2] 27 ae [2] 09 8c [2] 1d 97 [2] 12 8d [2] 0c 90 [2] 0e 91 [2] 15 97 [2] 09 90 [2] 15 bf }

  condition:
    any of them
}