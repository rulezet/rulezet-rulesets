rule TTP_XOR_QUAD_CurrentVersionRun_fa51 {
  strings:
    $key_fa51 = { a9 3e [2] 8d 30 [2] a6 1c [2] 88 3e [2] 9c 25 [2] 93 3f [2] 8d 22 [2] 8f 23 [2] 94 25 [2] 88 22 [2] 94 0d }

  condition:
    any of them
}