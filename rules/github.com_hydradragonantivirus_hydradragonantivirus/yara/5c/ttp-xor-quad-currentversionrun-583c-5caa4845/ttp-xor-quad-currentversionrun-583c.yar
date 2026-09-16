rule TTP_XOR_QUAD_CurrentVersionRun_583c {
  strings:
    $key_583c = { 0b 53 [2] 2f 5d [2] 04 71 [2] 2a 53 [2] 3e 48 [2] 31 52 [2] 2f 4f [2] 2d 4e [2] 36 48 [2] 2a 4f [2] 36 60 }

  condition:
    any of them
}