rule TTP_XOR_QUAD_CurrentVersionRun_57e3 {
  strings:
    $key_57e3 = { 04 8c [2] 20 82 [2] 0b ae [2] 25 8c [2] 31 97 [2] 3e 8d [2] 20 90 [2] 22 91 [2] 39 97 [2] 25 90 [2] 39 bf }

  condition:
    any of them
}