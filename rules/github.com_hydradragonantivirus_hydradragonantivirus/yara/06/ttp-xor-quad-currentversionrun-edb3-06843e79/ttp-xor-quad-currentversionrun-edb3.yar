rule TTP_XOR_QUAD_CurrentVersionRun_edb3 {
  strings:
    $key_edb3 = { be dc [2] 9a d2 [2] b1 fe [2] 9f dc [2] 8b c7 [2] 84 dd [2] 9a c0 [2] 98 c1 [2] 83 c7 [2] 9f c0 [2] 83 ef }

  condition:
    any of them
}