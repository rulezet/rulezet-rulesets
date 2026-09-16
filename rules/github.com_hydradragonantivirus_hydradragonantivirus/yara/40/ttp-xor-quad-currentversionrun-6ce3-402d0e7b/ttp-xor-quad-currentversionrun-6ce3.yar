rule TTP_XOR_QUAD_CurrentVersionRun_6ce3 {
  strings:
    $key_6ce3 = { 3f 8c [2] 1b 82 [2] 30 ae [2] 1e 8c [2] 0a 97 [2] 05 8d [2] 1b 90 [2] 19 91 [2] 02 97 [2] 1e 90 [2] 02 bf }

  condition:
    any of them
}