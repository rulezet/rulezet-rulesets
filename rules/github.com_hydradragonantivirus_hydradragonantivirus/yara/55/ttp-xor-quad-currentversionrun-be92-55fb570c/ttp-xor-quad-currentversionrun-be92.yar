rule TTP_XOR_QUAD_CurrentVersionRun_be92 {
  strings:
    $key_be92 = { ed fd [2] c9 f3 [2] e2 df [2] cc fd [2] d8 e6 [2] d7 fc [2] c9 e1 [2] cb e0 [2] d0 e6 [2] cc e1 [2] d0 ce }

  condition:
    any of them
}