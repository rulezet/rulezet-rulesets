rule TTP_XOR_QUAD_CurrentVersionRun_2bfb {
  strings:
    $key_2bfb = { 78 94 [2] 5c 9a [2] 77 b6 [2] 59 94 [2] 4d 8f [2] 42 95 [2] 5c 88 [2] 5e 89 [2] 45 8f [2] 59 88 [2] 45 a7 }

  condition:
    any of them
}