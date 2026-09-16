rule TTP_XOR_QUAD_CurrentVersionRun_fa32 {
  strings:
    $key_fa32 = { a9 5d [2] 8d 53 [2] a6 7f [2] 88 5d [2] 9c 46 [2] 93 5c [2] 8d 41 [2] 8f 40 [2] 94 46 [2] 88 41 [2] 94 6e }

  condition:
    any of them
}