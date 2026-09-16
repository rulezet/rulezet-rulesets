rule TTP_XOR_QUAD_CurrentVersionRun_27e3 {
  strings:
    $key_27e3 = { 74 8c [2] 50 82 [2] 7b ae [2] 55 8c [2] 41 97 [2] 4e 8d [2] 50 90 [2] 52 91 [2] 49 97 [2] 55 90 [2] 49 bf }

  condition:
    any of them
}