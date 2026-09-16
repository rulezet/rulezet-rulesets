rule TTP_XOR_QUAD_CurrentVersionRun_17e3 {
  strings:
    $key_17e3 = { 44 8c [2] 60 82 [2] 4b ae [2] 65 8c [2] 71 97 [2] 7e 8d [2] 60 90 [2] 62 91 [2] 79 97 [2] 65 90 [2] 79 bf }

  condition:
    any of them
}