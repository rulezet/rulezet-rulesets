rule TTP_XOR_QUAD_CurrentVersionRun_6e62 {
  strings:
    $key_6e62 = { 3d 0d [2] 19 03 [2] 32 2f [2] 1c 0d [2] 08 16 [2] 07 0c [2] 19 11 [2] 1b 10 [2] 00 16 [2] 1c 11 [2] 00 3e }

  condition:
    any of them
}