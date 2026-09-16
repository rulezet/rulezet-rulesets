rule TTP_XOR_QUAD_CurrentVersionRun_fde3 {
  strings:
    $key_fde3 = { ae 8c [2] 8a 82 [2] a1 ae [2] 8f 8c [2] 9b 97 [2] 94 8d [2] 8a 90 [2] 88 91 [2] 93 97 [2] 8f 90 [2] 93 bf }

  condition:
    any of them
}