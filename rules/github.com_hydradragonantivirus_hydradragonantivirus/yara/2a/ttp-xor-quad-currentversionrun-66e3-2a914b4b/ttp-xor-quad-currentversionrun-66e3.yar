rule TTP_XOR_QUAD_CurrentVersionRun_66e3 {
  strings:
    $key_66e3 = { 35 8c [2] 11 82 [2] 3a ae [2] 14 8c [2] 00 97 [2] 0f 8d [2] 11 90 [2] 13 91 [2] 08 97 [2] 14 90 [2] 08 bf }

  condition:
    any of them
}