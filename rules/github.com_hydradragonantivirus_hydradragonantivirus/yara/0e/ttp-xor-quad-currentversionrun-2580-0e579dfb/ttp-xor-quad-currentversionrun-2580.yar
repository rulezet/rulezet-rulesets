rule TTP_XOR_QUAD_CurrentVersionRun_2580 {
  strings:
    $key_2580 = { 76 ef [2] 52 e1 [2] 79 cd [2] 57 ef [2] 43 f4 [2] 4c ee [2] 52 f3 [2] 50 f2 [2] 4b f4 [2] 57 f3 [2] 4b dc }

  condition:
    any of them
}