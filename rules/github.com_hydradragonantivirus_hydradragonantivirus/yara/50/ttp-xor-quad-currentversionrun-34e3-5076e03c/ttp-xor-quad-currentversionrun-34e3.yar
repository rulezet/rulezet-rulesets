rule TTP_XOR_QUAD_CurrentVersionRun_34e3 {
  strings:
    $key_34e3 = { 67 8c [2] 43 82 [2] 68 ae [2] 46 8c [2] 52 97 [2] 5d 8d [2] 43 90 [2] 41 91 [2] 5a 97 [2] 46 90 [2] 5a bf }

  condition:
    any of them
}