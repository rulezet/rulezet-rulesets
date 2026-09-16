rule TTP_XOR_QUAD_CurrentVersionRun_513c {
  strings:
    $key_513c = { 02 53 [2] 26 5d [2] 0d 71 [2] 23 53 [2] 37 48 [2] 38 52 [2] 26 4f [2] 24 4e [2] 3f 48 [2] 23 4f [2] 3f 60 }

  condition:
    any of them
}