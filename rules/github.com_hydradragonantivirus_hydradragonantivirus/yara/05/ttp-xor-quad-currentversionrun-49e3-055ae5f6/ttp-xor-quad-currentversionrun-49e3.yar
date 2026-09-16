rule TTP_XOR_QUAD_CurrentVersionRun_49e3 {
  strings:
    $key_49e3 = { 1a 8c [2] 3e 82 [2] 15 ae [2] 3b 8c [2] 2f 97 [2] 20 8d [2] 3e 90 [2] 3c 91 [2] 27 97 [2] 3b 90 [2] 27 bf }

  condition:
    any of them
}