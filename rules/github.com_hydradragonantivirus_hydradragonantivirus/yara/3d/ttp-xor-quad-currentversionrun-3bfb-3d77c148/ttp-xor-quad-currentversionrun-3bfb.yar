rule TTP_XOR_QUAD_CurrentVersionRun_3bfb {
  strings:
    $key_3bfb = { 68 94 [2] 4c 9a [2] 67 b6 [2] 49 94 [2] 5d 8f [2] 52 95 [2] 4c 88 [2] 4e 89 [2] 55 8f [2] 49 88 [2] 55 a7 }

  condition:
    any of them
}