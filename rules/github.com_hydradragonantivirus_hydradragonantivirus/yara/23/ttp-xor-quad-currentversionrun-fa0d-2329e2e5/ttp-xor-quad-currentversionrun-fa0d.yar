rule TTP_XOR_QUAD_CurrentVersionRun_fa0d {
  strings:
    $key_fa0d = { a9 62 [2] 8d 6c [2] a6 40 [2] 88 62 [2] 9c 79 [2] 93 63 [2] 8d 7e [2] 8f 7f [2] 94 79 [2] 88 7e [2] 94 51 }

  condition:
    any of them
}