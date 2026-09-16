rule TTP_XOR_QUAD_CurrentVersionRun_431c {
  strings:
    $key_431c = { 10 73 [2] 34 7d [2] 1f 51 [2] 31 73 [2] 25 68 [2] 2a 72 [2] 34 6f [2] 36 6e [2] 2d 68 [2] 31 6f [2] 2d 40 }

  condition:
    any of them
}