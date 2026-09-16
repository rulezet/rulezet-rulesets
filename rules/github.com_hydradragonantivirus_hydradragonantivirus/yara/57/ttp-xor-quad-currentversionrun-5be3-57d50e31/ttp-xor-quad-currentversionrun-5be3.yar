rule TTP_XOR_QUAD_CurrentVersionRun_5be3 {
  strings:
    $key_5be3 = { 08 8c [2] 2c 82 [2] 07 ae [2] 29 8c [2] 3d 97 [2] 32 8d [2] 2c 90 [2] 2e 91 [2] 35 97 [2] 29 90 [2] 35 bf }

  condition:
    any of them
}