rule TTP_XOR_QUAD_CurrentVersionRun_6d10 {
  strings:
    $key_6d10 = { 3e 7f [2] 1a 71 [2] 31 5d [2] 1f 7f [2] 0b 64 [2] 04 7e [2] 1a 63 [2] 18 62 [2] 03 64 [2] 1f 63 [2] 03 4c }

  condition:
    any of them
}