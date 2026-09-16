rule TTP_XOR_QUAD_CurrentVersionRun_56e3 {
  strings:
    $key_56e3 = { 05 8c [2] 21 82 [2] 0a ae [2] 24 8c [2] 30 97 [2] 3f 8d [2] 21 90 [2] 23 91 [2] 38 97 [2] 24 90 [2] 38 bf }

  condition:
    any of them
}