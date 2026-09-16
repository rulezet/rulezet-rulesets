rule TTP_XOR_QUAD_CurrentVersionRun_980f {
  strings:
    $key_980f = { cb 60 [2] ef 6e [2] c4 42 [2] ea 60 [2] fe 7b [2] f1 61 [2] ef 7c [2] ed 7d [2] f6 7b [2] ea 7c [2] f6 53 }

  condition:
    any of them
}