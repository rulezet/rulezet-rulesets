rule TTP_XOR_QUAD_CurrentVersionRun_fcb3 {
  strings:
    $key_fcb3 = { af dc [2] 8b d2 [2] a0 fe [2] 8e dc [2] 9a c7 [2] 95 dd [2] 8b c0 [2] 89 c1 [2] 92 c7 [2] 8e c0 [2] 92 ef }

  condition:
    any of them
}