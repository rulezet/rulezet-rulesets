rule TTP_XOR_QUAD_CurrentVersionRun_98ff {
  strings:
    $key_98ff = { cb 90 [2] ef 9e [2] c4 b2 [2] ea 90 [2] fe 8b [2] f1 91 [2] ef 8c [2] ed 8d [2] f6 8b [2] ea 8c [2] f6 a3 }

  condition:
    any of them
}