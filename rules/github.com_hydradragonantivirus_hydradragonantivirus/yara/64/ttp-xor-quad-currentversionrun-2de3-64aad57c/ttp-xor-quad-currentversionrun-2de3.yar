rule TTP_XOR_QUAD_CurrentVersionRun_2de3 {
  strings:
    $key_2de3 = { 7e 8c [2] 5a 82 [2] 71 ae [2] 5f 8c [2] 4b 97 [2] 44 8d [2] 5a 90 [2] 58 91 [2] 43 97 [2] 5f 90 [2] 43 bf }

  condition:
    any of them
}