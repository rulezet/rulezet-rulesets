rule TTP_XOR_QUAD_CurrentVersionRun_2a10 {
  strings:
    $key_2a10 = { 79 7f [2] 5d 71 [2] 76 5d [2] 58 7f [2] 4c 64 [2] 43 7e [2] 5d 63 [2] 5f 62 [2] 44 64 [2] 58 63 [2] 44 4c }

  condition:
    any of them
}