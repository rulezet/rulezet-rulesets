rule TTP_XOR_QUAD_CurrentVersionRun_810f {
  strings:
    $key_810f = { d2 60 [2] f6 6e [2] dd 42 [2] f3 60 [2] e7 7b [2] e8 61 [2] f6 7c [2] f4 7d [2] ef 7b [2] f3 7c [2] ef 53 }

  condition:
    any of them
}