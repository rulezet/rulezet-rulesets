rule TTP_XOR_QUAD_CurrentVersionRun_fa0c {
  strings:
    $key_fa0c = { a9 63 [2] 8d 6d [2] a6 41 [2] 88 63 [2] 9c 78 [2] 93 62 [2] 8d 7f [2] 8f 7e [2] 94 78 [2] 88 7f [2] 94 50 }

  condition:
    any of them
}