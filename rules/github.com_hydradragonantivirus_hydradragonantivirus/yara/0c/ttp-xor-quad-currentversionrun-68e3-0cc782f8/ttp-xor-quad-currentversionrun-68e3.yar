rule TTP_XOR_QUAD_CurrentVersionRun_68e3 {
  strings:
    $key_68e3 = { 3b 8c [2] 1f 82 [2] 34 ae [2] 1a 8c [2] 0e 97 [2] 01 8d [2] 1f 90 [2] 1d 91 [2] 06 97 [2] 1a 90 [2] 06 bf }

  condition:
    any of them
}