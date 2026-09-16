rule TTP_XOR_QUAD_CurrentVersionRun_8bdc {
  strings:
    $key_8bdc = { d8 b3 [2] fc bd [2] d7 91 [2] f9 b3 [2] ed a8 [2] e2 b2 [2] fc af [2] fe ae [2] e5 a8 [2] f9 af [2] e5 80 }

  condition:
    any of them
}