rule TTP_XOR_QUAD_CurrentVersionRun_0db3 {
  strings:
    $key_0db3 = { 5e dc [2] 7a d2 [2] 51 fe [2] 7f dc [2] 6b c7 [2] 64 dd [2] 7a c0 [2] 78 c1 [2] 63 c7 [2] 7f c0 [2] 63 ef }

  condition:
    any of them
}