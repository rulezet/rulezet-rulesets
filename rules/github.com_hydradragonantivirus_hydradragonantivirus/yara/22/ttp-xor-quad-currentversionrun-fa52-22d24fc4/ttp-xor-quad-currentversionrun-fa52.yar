rule TTP_XOR_QUAD_CurrentVersionRun_fa52 {
  strings:
    $key_fa52 = { a9 3d [2] 8d 33 [2] a6 1f [2] 88 3d [2] 9c 26 [2] 93 3c [2] 8d 21 [2] 8f 20 [2] 94 26 [2] 88 21 [2] 94 0e }

  condition:
    any of them
}