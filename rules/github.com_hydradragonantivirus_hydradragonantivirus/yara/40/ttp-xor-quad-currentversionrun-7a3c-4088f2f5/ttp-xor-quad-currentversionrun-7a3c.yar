rule TTP_XOR_QUAD_CurrentVersionRun_7a3c {
  strings:
    $key_7a3c = { 29 53 [2] 0d 5d [2] 26 71 [2] 08 53 [2] 1c 48 [2] 13 52 [2] 0d 4f [2] 0f 4e [2] 14 48 [2] 08 4f [2] 14 60 }

  condition:
    any of them
}