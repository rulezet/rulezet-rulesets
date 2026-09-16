rule TTP_XOR_QUAD_CurrentVersionRun_503c {
  strings:
    $key_503c = { 03 53 [2] 27 5d [2] 0c 71 [2] 22 53 [2] 36 48 [2] 39 52 [2] 27 4f [2] 25 4e [2] 3e 48 [2] 22 4f [2] 3e 60 }

  condition:
    any of them
}