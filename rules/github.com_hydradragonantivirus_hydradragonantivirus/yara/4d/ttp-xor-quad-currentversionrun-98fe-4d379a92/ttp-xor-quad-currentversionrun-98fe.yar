rule TTP_XOR_QUAD_CurrentVersionRun_98fe {
  strings:
    $key_98fe = { cb 91 [2] ef 9f [2] c4 b3 [2] ea 91 [2] fe 8a [2] f1 90 [2] ef 8d [2] ed 8c [2] f6 8a [2] ea 8d [2] f6 a2 }

  condition:
    any of them
}