rule TTP_XOR_QUAD_CurrentVersionRun_e1e3 {
  strings:
    $key_e1e3 = { b2 8c [2] 96 82 [2] bd ae [2] 93 8c [2] 87 97 [2] 88 8d [2] 96 90 [2] 94 91 [2] 8f 97 [2] 93 90 [2] 8f bf }

  condition:
    any of them
}