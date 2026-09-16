rule TTP_XOR_QUAD_CurrentVersionRun_bf92 {
  strings:
    $key_bf92 = { ec fd [2] c8 f3 [2] e3 df [2] cd fd [2] d9 e6 [2] d6 fc [2] c8 e1 [2] ca e0 [2] d1 e6 [2] cd e1 [2] d1 ce }

  condition:
    any of them
}