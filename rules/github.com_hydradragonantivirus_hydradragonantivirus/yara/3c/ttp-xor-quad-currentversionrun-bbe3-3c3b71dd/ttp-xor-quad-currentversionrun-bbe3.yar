rule TTP_XOR_QUAD_CurrentVersionRun_bbe3 {
  strings:
    $key_bbe3 = { e8 8c [2] cc 82 [2] e7 ae [2] c9 8c [2] dd 97 [2] d2 8d [2] cc 90 [2] ce 91 [2] d5 97 [2] c9 90 [2] d5 bf }

  condition:
    any of them
}