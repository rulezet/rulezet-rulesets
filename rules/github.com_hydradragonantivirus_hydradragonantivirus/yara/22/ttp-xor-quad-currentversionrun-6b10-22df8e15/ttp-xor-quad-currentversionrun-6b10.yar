rule TTP_XOR_QUAD_CurrentVersionRun_6b10 {
  strings:
    $key_6b10 = { 38 7f [2] 1c 71 [2] 37 5d [2] 19 7f [2] 0d 64 [2] 02 7e [2] 1c 63 [2] 1e 62 [2] 05 64 [2] 19 63 [2] 05 4c }

  condition:
    any of them
}