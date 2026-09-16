rule TTP_XOR_QUAD_CurrentVersionRun_46e3 {
  strings:
    $key_46e3 = { 15 8c [2] 31 82 [2] 1a ae [2] 34 8c [2] 20 97 [2] 2f 8d [2] 31 90 [2] 33 91 [2] 28 97 [2] 34 90 [2] 28 bf }

  condition:
    any of them
}