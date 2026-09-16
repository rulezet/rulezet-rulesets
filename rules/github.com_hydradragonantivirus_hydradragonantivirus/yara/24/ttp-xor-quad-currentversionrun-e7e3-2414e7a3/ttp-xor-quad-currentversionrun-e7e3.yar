rule TTP_XOR_QUAD_CurrentVersionRun_e7e3 {
  strings:
    $key_e7e3 = { b4 8c [2] 90 82 [2] bb ae [2] 95 8c [2] 81 97 [2] 8e 8d [2] 90 90 [2] 92 91 [2] 89 97 [2] 95 90 [2] 89 bf }

  condition:
    any of them
}