rule TTP_XOR_QUAD_CurrentVersionRun_948c {
  strings:
    $key_948c = { c7 e3 [2] e3 ed [2] c8 c1 [2] e6 e3 [2] f2 f8 [2] fd e2 [2] e3 ff [2] e1 fe [2] fa f8 [2] e6 ff [2] fa d0 }

  condition:
    any of them
}