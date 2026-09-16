rule TTP_XOR_QUAD_CurrentVersionRun_1ee3 {
  strings:
    $key_1ee3 = { 4d 8c [2] 69 82 [2] 42 ae [2] 6c 8c [2] 78 97 [2] 77 8d [2] 69 90 [2] 6b 91 [2] 70 97 [2] 6c 90 [2] 70 bf }

  condition:
    any of them
}