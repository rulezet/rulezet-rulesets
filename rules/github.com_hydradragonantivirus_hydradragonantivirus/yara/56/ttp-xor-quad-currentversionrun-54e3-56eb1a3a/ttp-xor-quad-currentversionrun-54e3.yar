rule TTP_XOR_QUAD_CurrentVersionRun_54e3 {
  strings:
    $key_54e3 = { 07 8c [2] 23 82 [2] 08 ae [2] 26 8c [2] 32 97 [2] 3d 8d [2] 23 90 [2] 21 91 [2] 3a 97 [2] 26 90 [2] 3a bf }

  condition:
    any of them
}