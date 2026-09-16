rule TTP_XOR_QUAD_CurrentVersionRun_5f3c {
  strings:
    $key_5f3c = { 0c 53 [2] 28 5d [2] 03 71 [2] 2d 53 [2] 39 48 [2] 36 52 [2] 28 4f [2] 2a 4e [2] 31 48 [2] 2d 4f [2] 31 60 }

  condition:
    any of them
}