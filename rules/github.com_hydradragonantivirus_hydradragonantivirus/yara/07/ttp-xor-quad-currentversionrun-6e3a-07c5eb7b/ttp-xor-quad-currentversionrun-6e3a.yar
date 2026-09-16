rule TTP_XOR_QUAD_CurrentVersionRun_6e3a {
  strings:
    $key_6e3a = { 3d 55 [2] 19 5b [2] 32 77 [2] 1c 55 [2] 08 4e [2] 07 54 [2] 19 49 [2] 1b 48 [2] 00 4e [2] 1c 49 [2] 00 66 }

  condition:
    any of them
}