rule TTP_XOR_QUAD_CurrentVersionRun_cdb3 {
  strings:
    $key_cdb3 = { 9e dc [2] ba d2 [2] 91 fe [2] bf dc [2] ab c7 [2] a4 dd [2] ba c0 [2] b8 c1 [2] a3 c7 [2] bf c0 [2] a3 ef }

  condition:
    any of them
}