rule TTP_XOR_QUAD_CurrentVersionRun_d892 {
  strings:
    $key_d892 = { 8b fd [2] af f3 [2] 84 df [2] aa fd [2] be e6 [2] b1 fc [2] af e1 [2] ad e0 [2] b6 e6 [2] aa e1 [2] b6 ce }

  condition:
    any of them
}