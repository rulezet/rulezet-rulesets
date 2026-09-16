rule TTP_XOR_QUAD_CurrentVersionRun_6e21 {
  strings:
    $key_6e21 = { 3d 4e [2] 19 40 [2] 32 6c [2] 1c 4e [2] 08 55 [2] 07 4f [2] 19 52 [2] 1b 53 [2] 00 55 [2] 1c 52 [2] 00 7d }

  condition:
    any of them
}