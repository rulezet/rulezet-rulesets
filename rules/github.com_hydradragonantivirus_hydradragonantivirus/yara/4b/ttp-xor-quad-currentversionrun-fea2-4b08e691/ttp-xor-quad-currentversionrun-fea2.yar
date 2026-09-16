rule TTP_XOR_QUAD_CurrentVersionRun_fea2 {
  strings:
    $key_fea2 = { ad cd [2] 89 c3 [2] a2 ef [2] 8c cd [2] 98 d6 [2] 97 cc [2] 89 d1 [2] 8b d0 [2] 90 d6 [2] 8c d1 [2] 90 fe }

  condition:
    any of them
}