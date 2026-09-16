rule TTP_XOR_QUAD_CurrentVersionRun_7580 {
  strings:
    $key_7580 = { 26 ef [2] 02 e1 [2] 29 cd [2] 07 ef [2] 13 f4 [2] 1c ee [2] 02 f3 [2] 00 f2 [2] 1b f4 [2] 07 f3 [2] 1b dc }

  condition:
    any of them
}