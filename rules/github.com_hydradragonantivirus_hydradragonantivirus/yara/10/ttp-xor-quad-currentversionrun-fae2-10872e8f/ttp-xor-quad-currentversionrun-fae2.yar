rule TTP_XOR_QUAD_CurrentVersionRun_fae2 {
  strings:
    $key_fae2 = { a9 8d [2] 8d 83 [2] a6 af [2] 88 8d [2] 9c 96 [2] 93 8c [2] 8d 91 [2] 8f 90 [2] 94 96 [2] 88 91 [2] 94 be }

  condition:
    any of them
}