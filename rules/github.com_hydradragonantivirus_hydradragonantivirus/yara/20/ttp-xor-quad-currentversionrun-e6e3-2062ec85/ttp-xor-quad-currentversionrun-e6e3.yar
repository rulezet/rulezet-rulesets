rule TTP_XOR_QUAD_CurrentVersionRun_e6e3 {
  strings:
    $key_e6e3 = { b5 8c [2] 91 82 [2] ba ae [2] 94 8c [2] 80 97 [2] 8f 8d [2] 91 90 [2] 93 91 [2] 88 97 [2] 94 90 [2] 88 bf }

  condition:
    any of them
}