rule TTP_XOR_QUAD_CurrentVersionRun_8cfe {
  strings:
    $key_8cfe = { df 91 [2] fb 9f [2] d0 b3 [2] fe 91 [2] ea 8a [2] e5 90 [2] fb 8d [2] f9 8c [2] e2 8a [2] fe 8d [2] e2 a2 }

  condition:
    any of them
}