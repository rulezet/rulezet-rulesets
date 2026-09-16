rule TTP_XOR_QUAD_CurrentVersionRun_ba92 {
  strings:
    $key_ba92 = { e9 fd [2] cd f3 [2] e6 df [2] c8 fd [2] dc e6 [2] d3 fc [2] cd e1 [2] cf e0 [2] d4 e6 [2] c8 e1 [2] d4 ce }

  condition:
    any of them
}