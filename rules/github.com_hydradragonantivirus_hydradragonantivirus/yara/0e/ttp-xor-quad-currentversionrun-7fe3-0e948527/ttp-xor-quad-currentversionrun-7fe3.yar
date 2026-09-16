rule TTP_XOR_QUAD_CurrentVersionRun_7fe3 {
  strings:
    $key_7fe3 = { 2c 8c [2] 08 82 [2] 23 ae [2] 0d 8c [2] 19 97 [2] 16 8d [2] 08 90 [2] 0a 91 [2] 11 97 [2] 0d 90 [2] 11 bf }

  condition:
    any of them
}