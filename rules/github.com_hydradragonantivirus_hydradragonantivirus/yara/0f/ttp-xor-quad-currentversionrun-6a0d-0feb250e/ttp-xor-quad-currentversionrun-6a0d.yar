rule TTP_XOR_QUAD_CurrentVersionRun_6a0d {
  strings:
    $key_6a0d = { 39 62 [2] 1d 6c [2] 36 40 [2] 18 62 [2] 0c 79 [2] 03 63 [2] 1d 7e [2] 1f 7f [2] 04 79 [2] 18 7e [2] 04 51 }

  condition:
    any of them
}