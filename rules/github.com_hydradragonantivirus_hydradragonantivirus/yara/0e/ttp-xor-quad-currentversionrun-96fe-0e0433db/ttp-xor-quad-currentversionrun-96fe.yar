rule TTP_XOR_QUAD_CurrentVersionRun_96fe {
  strings:
    $key_96fe = { c5 91 [2] e1 9f [2] ca b3 [2] e4 91 [2] f0 8a [2] ff 90 [2] e1 8d [2] e3 8c [2] f8 8a [2] e4 8d [2] f8 a2 }

  condition:
    any of them
}