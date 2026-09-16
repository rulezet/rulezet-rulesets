rule TTP_XOR_QUAD_CurrentVersionRun_da83 {
  strings:
    $key_da83 = { 89 ec [2] ad e2 [2] 86 ce [2] a8 ec [2] bc f7 [2] b3 ed [2] ad f0 [2] af f1 [2] b4 f7 [2] a8 f0 [2] b4 df }

  condition:
    any of them
}