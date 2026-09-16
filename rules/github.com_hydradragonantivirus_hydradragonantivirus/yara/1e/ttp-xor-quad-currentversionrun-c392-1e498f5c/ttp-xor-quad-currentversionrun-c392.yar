rule TTP_XOR_QUAD_CurrentVersionRun_c392 {
  strings:
    $key_c392 = { 90 fd [2] b4 f3 [2] 9f df [2] b1 fd [2] a5 e6 [2] aa fc [2] b4 e1 [2] b6 e0 [2] ad e6 [2] b1 e1 [2] ad ce }

  condition:
    any of them
}