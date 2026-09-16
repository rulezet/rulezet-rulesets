rule TTP_XOR_QUAD_CurrentVersionRun_6e3d {
  strings:
    $key_6e3d = { 3d 52 [2] 19 5c [2] 32 70 [2] 1c 52 [2] 08 49 [2] 07 53 [2] 19 4e [2] 1b 4f [2] 00 49 [2] 1c 4e [2] 00 61 }

  condition:
    any of them
}