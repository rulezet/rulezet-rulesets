rule TTP_XOR_QUAD_CurrentVersionRun_0580 {
  strings:
    $key_0580 = { 56 ef [2] 72 e1 [2] 59 cd [2] 77 ef [2] 63 f4 [2] 6c ee [2] 72 f3 [2] 70 f2 [2] 6b f4 [2] 77 f3 [2] 6b dc }

  condition:
    any of them
}