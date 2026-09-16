rule TTP_XOR_QUAD_CurrentVersionRun_1f3c {
  strings:
    $key_1f3c = { 4c 53 [2] 68 5d [2] 43 71 [2] 6d 53 [2] 79 48 [2] 76 52 [2] 68 4f [2] 6a 4e [2] 71 48 [2] 6d 4f [2] 71 60 }

  condition:
    any of them
}