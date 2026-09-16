rule TTP_XOR_QUAD_CurrentVersionRun_580d {
  strings:
    $key_580d = { 0b 62 [2] 2f 6c [2] 04 40 [2] 2a 62 [2] 3e 79 [2] 31 63 [2] 2f 7e [2] 2d 7f [2] 36 79 [2] 2a 7e [2] 36 51 }

  condition:
    any of them
}