rule TTP_XOR_QUAD_CurrentVersionRun_93fe {
  strings:
    $key_93fe = { c0 91 [2] e4 9f [2] cf b3 [2] e1 91 [2] f5 8a [2] fa 90 [2] e4 8d [2] e6 8c [2] fd 8a [2] e1 8d [2] fd a2 }

  condition:
    any of them
}