rule TTP_XOR_QUAD_CurrentVersionRun_c492 {
  strings:
    $key_c492 = { 97 fd [2] b3 f3 [2] 98 df [2] b6 fd [2] a2 e6 [2] ad fc [2] b3 e1 [2] b1 e0 [2] aa e6 [2] b6 e1 [2] aa ce }

  condition:
    any of them
}