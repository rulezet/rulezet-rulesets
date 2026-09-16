rule TTP_XOR_QUAD_CurrentVersionRun_180d {
  strings:
    $key_180d = { 4b 62 [2] 6f 6c [2] 44 40 [2] 6a 62 [2] 7e 79 [2] 71 63 [2] 6f 7e [2] 6d 7f [2] 76 79 [2] 6a 7e [2] 76 51 }

  condition:
    any of them
}