rule TTP_XOR_QUAD_CurrentVersionRun_da91 {
  strings:
    $key_da91 = { 89 fe [2] ad f0 [2] 86 dc [2] a8 fe [2] bc e5 [2] b3 ff [2] ad e2 [2] af e3 [2] b4 e5 [2] a8 e2 [2] b4 cd }

  condition:
    any of them
}