rule TTP_XOR_QUAD_CurrentVersionRun_160d {
  strings:
    $key_160d = { 45 62 [2] 61 6c [2] 4a 40 [2] 64 62 [2] 70 79 [2] 7f 63 [2] 61 7e [2] 63 7f [2] 78 79 [2] 64 7e [2] 78 51 }

  condition:
    any of them
}