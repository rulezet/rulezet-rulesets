rule TTP_XOR_QUAD_CurrentVersionRun_6b62 {
  strings:
    $key_6b62 = { 38 0d [2] 1c 03 [2] 37 2f [2] 19 0d [2] 0d 16 [2] 02 0c [2] 1c 11 [2] 1e 10 [2] 05 16 [2] 19 11 [2] 05 3e }

  condition:
    any of them
}