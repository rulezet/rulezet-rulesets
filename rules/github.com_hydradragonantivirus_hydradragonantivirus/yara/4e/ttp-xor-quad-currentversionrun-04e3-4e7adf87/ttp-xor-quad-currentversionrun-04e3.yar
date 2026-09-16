rule TTP_XOR_QUAD_CurrentVersionRun_04e3 {
  strings:
    $key_04e3 = { 57 8c [2] 73 82 [2] 58 ae [2] 76 8c [2] 62 97 [2] 6d 8d [2] 73 90 [2] 71 91 [2] 6a 97 [2] 76 90 [2] 6a bf }

  condition:
    any of them
}