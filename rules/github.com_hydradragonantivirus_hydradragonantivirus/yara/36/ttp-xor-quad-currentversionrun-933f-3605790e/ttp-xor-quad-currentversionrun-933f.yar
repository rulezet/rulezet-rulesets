rule TTP_XOR_QUAD_CurrentVersionRun_933f {
  strings:
    $key_933f = { c0 50 [2] e4 5e [2] cf 72 [2] e1 50 [2] f5 4b [2] fa 51 [2] e4 4c [2] e6 4d [2] fd 4b [2] e1 4c [2] fd 63 }

  condition:
    any of them
}