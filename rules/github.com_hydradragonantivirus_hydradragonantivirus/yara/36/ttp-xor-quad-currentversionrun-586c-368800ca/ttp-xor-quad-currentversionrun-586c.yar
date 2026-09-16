rule TTP_XOR_QUAD_CurrentVersionRun_586c {
  strings:
    $key_586c = { 0b 03 [2] 2f 0d [2] 04 21 [2] 2a 03 [2] 3e 18 [2] 31 02 [2] 2f 1f [2] 2d 1e [2] 36 18 [2] 2a 1f [2] 36 30 }

  condition:
    any of them
}