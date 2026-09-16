rule TTP_XOR_QUAD_CurrentVersionRun_a892 {
  strings:
    $key_a892 = { fb fd [2] df f3 [2] f4 df [2] da fd [2] ce e6 [2] c1 fc [2] df e1 [2] dd e0 [2] c6 e6 [2] da e1 [2] c6 ce }

  condition:
    any of them
}