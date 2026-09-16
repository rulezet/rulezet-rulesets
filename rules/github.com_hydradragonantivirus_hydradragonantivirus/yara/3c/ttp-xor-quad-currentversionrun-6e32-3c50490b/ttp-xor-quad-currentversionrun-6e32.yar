rule TTP_XOR_QUAD_CurrentVersionRun_6e32 {
  strings:
    $key_6e32 = { 3d 5d [2] 19 53 [2] 32 7f [2] 1c 5d [2] 08 46 [2] 07 5c [2] 19 41 [2] 1b 40 [2] 00 46 [2] 1c 41 [2] 00 6e }

  condition:
    any of them
}