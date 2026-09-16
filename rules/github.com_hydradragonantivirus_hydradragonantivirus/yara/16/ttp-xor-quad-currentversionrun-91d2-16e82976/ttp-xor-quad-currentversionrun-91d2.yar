rule TTP_XOR_QUAD_CurrentVersionRun_91d2 {
  strings:
    $key_91d2 = { c2 bd [2] e6 b3 [2] cd 9f [2] e3 bd [2] f7 a6 [2] f8 bc [2] e6 a1 [2] e4 a0 [2] ff a6 [2] e3 a1 [2] ff 8e }

  condition:
    any of them
}