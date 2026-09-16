rule TTP_XOR_QUAD_CurrentVersionRun_8d0f {
  strings:
    $key_8d0f = { de 60 [2] fa 6e [2] d1 42 [2] ff 60 [2] eb 7b [2] e4 61 [2] fa 7c [2] f8 7d [2] e3 7b [2] ff 7c [2] e3 53 }

  condition:
    any of them
}