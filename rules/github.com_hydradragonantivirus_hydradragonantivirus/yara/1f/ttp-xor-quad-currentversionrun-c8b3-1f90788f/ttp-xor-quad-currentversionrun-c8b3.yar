rule TTP_XOR_QUAD_CurrentVersionRun_c8b3 {
  strings:
    $key_c8b3 = { 9b dc [2] bf d2 [2] 94 fe [2] ba dc [2] ae c7 [2] a1 dd [2] bf c0 [2] bd c1 [2] a6 c7 [2] ba c0 [2] a6 ef }

  condition:
    any of them
}