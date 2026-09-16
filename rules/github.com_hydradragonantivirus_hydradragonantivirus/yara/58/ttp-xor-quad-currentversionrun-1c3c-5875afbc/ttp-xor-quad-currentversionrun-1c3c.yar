rule TTP_XOR_QUAD_CurrentVersionRun_1c3c {
  strings:
    $key_1c3c = { 4f 53 [2] 6b 5d [2] 40 71 [2] 6e 53 [2] 7a 48 [2] 75 52 [2] 6b 4f [2] 69 4e [2] 72 48 [2] 6e 4f [2] 72 60 }

  condition:
    any of them
}