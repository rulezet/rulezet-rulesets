rule TTP_XOR_QUAD_CurrentVersionRun_37e3 {
  strings:
    $key_37e3 = { 64 8c [2] 40 82 [2] 6b ae [2] 45 8c [2] 51 97 [2] 5e 8d [2] 40 90 [2] 42 91 [2] 59 97 [2] 45 90 [2] 59 bf }

  condition:
    any of them
}