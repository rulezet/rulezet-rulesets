rule TTP_XOR_QUAD_CurrentVersionRun_48e3 {
  strings:
    $key_48e3 = { 1b 8c [2] 3f 82 [2] 14 ae [2] 3a 8c [2] 2e 97 [2] 21 8d [2] 3f 90 [2] 3d 91 [2] 26 97 [2] 3a 90 [2] 26 bf }

  condition:
    any of them
}