rule TTP_XOR_QUAD_CurrentVersionRun_2f10 {
  strings:
    $key_2f10 = { 7c 7f [2] 58 71 [2] 73 5d [2] 5d 7f [2] 49 64 [2] 46 7e [2] 58 63 [2] 5a 62 [2] 41 64 [2] 5d 63 [2] 41 4c }

  condition:
    any of them
}