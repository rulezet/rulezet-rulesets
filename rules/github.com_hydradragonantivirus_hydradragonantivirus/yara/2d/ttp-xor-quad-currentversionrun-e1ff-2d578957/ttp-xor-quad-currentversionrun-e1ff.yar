rule TTP_XOR_QUAD_CurrentVersionRun_e1ff {
  strings:
    $key_e1ff = { b2 90 [2] 96 9e [2] bd b2 [2] 93 90 [2] 87 8b [2] 88 91 [2] 96 8c [2] 94 8d [2] 8f 8b [2] 93 8c [2] 8f a3 }

  condition:
    any of them
}