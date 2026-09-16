rule TTP_XOR_QUAD_CurrentVersionRun_6b3c {
  strings:
    $key_6b3c = { 38 53 [2] 1c 5d [2] 37 71 [2] 19 53 [2] 0d 48 [2] 02 52 [2] 1c 4f [2] 1e 4e [2] 05 48 [2] 19 4f [2] 05 60 }

  condition:
    any of them
}