rule TTP_XOR_QUAD_CurrentVersionRun_6f3c {
  strings:
    $key_6f3c = { 3c 53 [2] 18 5d [2] 33 71 [2] 1d 53 [2] 09 48 [2] 06 52 [2] 18 4f [2] 1a 4e [2] 01 48 [2] 1d 4f [2] 01 60 }

  condition:
    any of them
}