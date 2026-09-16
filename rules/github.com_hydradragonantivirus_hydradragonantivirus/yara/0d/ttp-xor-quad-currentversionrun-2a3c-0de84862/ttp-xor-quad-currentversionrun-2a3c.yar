rule TTP_XOR_QUAD_CurrentVersionRun_2a3c {
  strings:
    $key_2a3c = { 79 53 [2] 5d 5d [2] 76 71 [2] 58 53 [2] 4c 48 [2] 43 52 [2] 5d 4f [2] 5f 4e [2] 44 48 [2] 58 4f [2] 44 60 }

  condition:
    any of them
}