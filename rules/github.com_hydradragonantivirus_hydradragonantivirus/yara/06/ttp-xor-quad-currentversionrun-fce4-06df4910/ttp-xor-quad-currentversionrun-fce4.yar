rule TTP_XOR_QUAD_CurrentVersionRun_fce4 {
  strings:
    $key_fce4 = { af 8b [2] 8b 85 [2] a0 a9 [2] 8e 8b [2] 9a 90 [2] 95 8a [2] 8b 97 [2] 89 96 [2] 92 90 [2] 8e 97 [2] 92 b8 }

  condition:
    any of them
}