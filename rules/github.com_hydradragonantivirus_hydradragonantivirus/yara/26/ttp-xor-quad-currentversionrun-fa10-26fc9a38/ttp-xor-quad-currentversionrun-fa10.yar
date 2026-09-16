rule TTP_XOR_QUAD_CurrentVersionRun_fa10 {
  strings:
    $key_fa10 = { a9 7f [2] 8d 71 [2] a6 5d [2] 88 7f [2] 9c 64 [2] 93 7e [2] 8d 63 [2] 8f 62 [2] 94 64 [2] 88 63 [2] 94 4c }

  condition:
    any of them
}