rule TTP_XOR_QUAD_CurrentVersionRun_4f3c {
  strings:
    $key_4f3c = { 1c 53 [2] 38 5d [2] 13 71 [2] 3d 53 [2] 29 48 [2] 26 52 [2] 38 4f [2] 3a 4e [2] 21 48 [2] 3d 4f [2] 21 60 }

  condition:
    any of them
}