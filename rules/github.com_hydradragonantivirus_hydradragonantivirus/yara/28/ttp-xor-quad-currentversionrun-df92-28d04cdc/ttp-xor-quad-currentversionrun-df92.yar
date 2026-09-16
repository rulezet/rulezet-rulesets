rule TTP_XOR_QUAD_CurrentVersionRun_df92 {
  strings:
    $key_df92 = { 8c fd [2] a8 f3 [2] 83 df [2] ad fd [2] b9 e6 [2] b6 fc [2] a8 e1 [2] aa e0 [2] b1 e6 [2] ad e1 [2] b1 ce }

  condition:
    any of them
}