rule TTP_XOR_QUAD_CurrentVersionRun_580c {
  strings:
    $key_580c = { 0b 63 [2] 2f 6d [2] 04 41 [2] 2a 63 [2] 3e 78 [2] 31 62 [2] 2f 7f [2] 2d 7e [2] 36 78 [2] 2a 7f [2] 36 50 }

  condition:
    any of them
}