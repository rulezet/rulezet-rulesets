rule TTP_XOR_QUAD_CurrentVersionRun_92a3 {
  strings:
    $key_92a3 = { c1 cc [2] e5 c2 [2] ce ee [2] e0 cc [2] f4 d7 [2] fb cd [2] e5 d0 [2] e7 d1 [2] fc d7 [2] e0 d0 [2] fc ff }

  condition:
    any of them
}