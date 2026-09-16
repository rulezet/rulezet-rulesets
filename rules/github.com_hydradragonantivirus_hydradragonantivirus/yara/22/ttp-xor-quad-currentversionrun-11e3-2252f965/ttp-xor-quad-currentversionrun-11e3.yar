rule TTP_XOR_QUAD_CurrentVersionRun_11e3 {
  strings:
    $key_11e3 = { 42 8c [2] 66 82 [2] 4d ae [2] 63 8c [2] 77 97 [2] 78 8d [2] 66 90 [2] 64 91 [2] 7f 97 [2] 63 90 [2] 7f bf }

  condition:
    any of them
}