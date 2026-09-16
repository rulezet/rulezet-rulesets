rule TTP_XOR_QUAD_CurrentVersionRun_92f0 {
  strings:
    $key_92f0 = { c1 9f [2] e5 91 [2] ce bd [2] e0 9f [2] f4 84 [2] fb 9e [2] e5 83 [2] e7 82 [2] fc 84 [2] e0 83 [2] fc ac }

  condition:
    any of them
}