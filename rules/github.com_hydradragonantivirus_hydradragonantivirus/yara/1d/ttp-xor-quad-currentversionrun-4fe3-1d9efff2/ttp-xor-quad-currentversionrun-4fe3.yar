rule TTP_XOR_QUAD_CurrentVersionRun_4fe3 {
  strings:
    $key_4fe3 = { 1c 8c [2] 38 82 [2] 13 ae [2] 3d 8c [2] 29 97 [2] 26 8d [2] 38 90 [2] 3a 91 [2] 21 97 [2] 3d 90 [2] 21 bf }

  condition:
    any of them
}