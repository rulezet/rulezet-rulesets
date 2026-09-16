rule TTP_XOR_QUAD_CurrentVersionRun_58e3 {
  strings:
    $key_58e3 = { 0b 8c [2] 2f 82 [2] 04 ae [2] 2a 8c [2] 3e 97 [2] 31 8d [2] 2f 90 [2] 2d 91 [2] 36 97 [2] 2a 90 [2] 36 bf }

  condition:
    any of them
}