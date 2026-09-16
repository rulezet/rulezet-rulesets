rule TTP_XOR_QUAD_CurrentVersionRun_d392 {
  strings:
    $key_d392 = { 80 fd [2] a4 f3 [2] 8f df [2] a1 fd [2] b5 e6 [2] ba fc [2] a4 e1 [2] a6 e0 [2] bd e6 [2] a1 e1 [2] bd ce }

  condition:
    any of them
}