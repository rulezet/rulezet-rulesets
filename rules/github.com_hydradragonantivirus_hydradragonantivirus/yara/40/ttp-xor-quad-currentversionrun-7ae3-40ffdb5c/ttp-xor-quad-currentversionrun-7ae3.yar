rule TTP_XOR_QUAD_CurrentVersionRun_7ae3 {
  strings:
    $key_7ae3 = { 29 8c [2] 0d 82 [2] 26 ae [2] 08 8c [2] 1c 97 [2] 13 8d [2] 0d 90 [2] 0f 91 [2] 14 97 [2] 08 90 [2] 14 bf }

  condition:
    any of them
}