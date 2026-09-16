rule TTP_XOR_QUAD_CurrentVersionRun_f992 {
  strings:
    $key_f992 = { aa fd [2] 8e f3 [2] a5 df [2] 8b fd [2] 9f e6 [2] 90 fc [2] 8e e1 [2] 8c e0 [2] 97 e6 [2] 8b e1 [2] 97 ce }

  condition:
    any of them
}