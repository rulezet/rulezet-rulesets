rule TTP_XOR_QUAD_CurrentVersionRun_c9a2 {
  strings:
    $key_c9a2 = { 9a cd [2] be c3 [2] 95 ef [2] bb cd [2] af d6 [2] a0 cc [2] be d1 [2] bc d0 [2] a7 d6 [2] bb d1 [2] a7 fe }

  condition:
    any of them
}