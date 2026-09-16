rule TTP_XOR_QUAD_CurrentVersionRun_1f0c {
  strings:
    $key_1f0c = { 4c 63 [2] 68 6d [2] 43 41 [2] 6d 63 [2] 79 78 [2] 76 62 [2] 68 7f [2] 6a 7e [2] 71 78 [2] 6d 7f [2] 71 50 }

  condition:
    any of them
}