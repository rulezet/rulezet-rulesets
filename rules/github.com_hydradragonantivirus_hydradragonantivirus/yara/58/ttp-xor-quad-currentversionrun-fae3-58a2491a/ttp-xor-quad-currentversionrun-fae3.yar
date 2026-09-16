rule TTP_XOR_QUAD_CurrentVersionRun_fae3 {
  strings:
    $key_fae3 = { a9 8c [2] 8d 82 [2] a6 ae [2] 88 8c [2] 9c 97 [2] 93 8d [2] 8d 90 [2] 8f 91 [2] 94 97 [2] 88 90 [2] 94 bf }

  condition:
    any of them
}