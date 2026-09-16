rule TTP_XOR_QUAD_CurrentVersionRun_3be3 {
  strings:
    $key_3be3 = { 68 8c [2] 4c 82 [2] 67 ae [2] 49 8c [2] 5d 97 [2] 52 8d [2] 4c 90 [2] 4e 91 [2] 55 97 [2] 49 90 [2] 55 bf }

  condition:
    any of them
}