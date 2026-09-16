rule TTP_XOR_QUAD_CurrentVersionRun_21e3 {
  strings:
    $key_21e3 = { 72 8c [2] 56 82 [2] 7d ae [2] 53 8c [2] 47 97 [2] 48 8d [2] 56 90 [2] 54 91 [2] 4f 97 [2] 53 90 [2] 4f bf }

  condition:
    any of them
}