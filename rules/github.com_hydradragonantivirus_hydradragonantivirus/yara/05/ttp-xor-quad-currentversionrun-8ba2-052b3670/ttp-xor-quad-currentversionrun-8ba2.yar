rule TTP_XOR_QUAD_CurrentVersionRun_8ba2 {
  strings:
    $key_8ba2 = { d8 cd [2] fc c3 [2] d7 ef [2] f9 cd [2] ed d6 [2] e2 cc [2] fc d1 [2] fe d0 [2] e5 d6 [2] f9 d1 [2] e5 fe }

  condition:
    any of them
}