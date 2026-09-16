rule TTP_XOR_QUAD_CurrentVersionRun_650d {
  strings:
    $key_650d = { 36 62 [2] 12 6c [2] 39 40 [2] 17 62 [2] 03 79 [2] 0c 63 [2] 12 7e [2] 10 7f [2] 0b 79 [2] 17 7e [2] 0b 51 }

  condition:
    any of them
}