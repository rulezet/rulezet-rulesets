rule TTP_XOR_QUAD_CurrentVersionRun_bcb1 {
  strings:
    $key_bcb1 = { ef de [2] cb d0 [2] e0 fc [2] ce de [2] da c5 [2] d5 df [2] cb c2 [2] c9 c3 [2] d2 c5 [2] ce c2 [2] d2 ed }

  condition:
    any of them
}