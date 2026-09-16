rule TTP_XOR_QUAD_CurrentVersionRun_ef92 {
  strings:
    $key_ef92 = { bc fd [2] 98 f3 [2] b3 df [2] 9d fd [2] 89 e6 [2] 86 fc [2] 98 e1 [2] 9a e0 [2] 81 e6 [2] 9d e1 [2] 81 ce }

  condition:
    any of them
}