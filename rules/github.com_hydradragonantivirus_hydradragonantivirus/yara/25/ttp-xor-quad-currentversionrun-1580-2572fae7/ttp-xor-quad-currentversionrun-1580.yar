rule TTP_XOR_QUAD_CurrentVersionRun_1580 {
  strings:
    $key_1580 = { 46 ef [2] 62 e1 [2] 49 cd [2] 67 ef [2] 73 f4 [2] 7c ee [2] 62 f3 [2] 60 f2 [2] 7b f4 [2] 67 f3 [2] 7b dc }

  condition:
    any of them
}