rule TTP_XOR_QUAD_CurrentVersionRun_5ae3 {
  strings:
    $key_5ae3 = { 09 8c [2] 2d 82 [2] 06 ae [2] 28 8c [2] 3c 97 [2] 33 8d [2] 2d 90 [2] 2f 91 [2] 34 97 [2] 28 90 [2] 34 bf }

  condition:
    any of them
}