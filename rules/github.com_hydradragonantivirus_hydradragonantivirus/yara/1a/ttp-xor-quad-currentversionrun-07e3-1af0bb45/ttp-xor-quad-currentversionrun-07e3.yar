rule TTP_XOR_QUAD_CurrentVersionRun_07e3 {
  strings:
    $key_07e3 = { 54 8c [2] 70 82 [2] 5b ae [2] 75 8c [2] 61 97 [2] 6e 8d [2] 70 90 [2] 72 91 [2] 69 97 [2] 75 90 [2] 69 bf }

  condition:
    any of them
}