rule TTP_XOR_QUAD_CurrentVersionRun_41e3 {
  strings:
    $key_41e3 = { 12 8c [2] 36 82 [2] 1d ae [2] 33 8c [2] 27 97 [2] 28 8d [2] 36 90 [2] 34 91 [2] 2f 97 [2] 33 90 [2] 2f bf }

  condition:
    any of them
}