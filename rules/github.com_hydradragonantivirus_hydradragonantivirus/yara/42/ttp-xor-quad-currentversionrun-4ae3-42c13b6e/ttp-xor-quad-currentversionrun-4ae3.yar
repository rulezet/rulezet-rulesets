rule TTP_XOR_QUAD_CurrentVersionRun_4ae3 {
  strings:
    $key_4ae3 = { 19 8c [2] 3d 82 [2] 16 ae [2] 38 8c [2] 2c 97 [2] 23 8d [2] 3d 90 [2] 3f 91 [2] 24 97 [2] 38 90 [2] 24 bf }

  condition:
    any of them
}