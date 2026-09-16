rule TTP_XOR_QUAD_CurrentVersionRun_933d {
  strings:
    $key_933d = { c0 52 [2] e4 5c [2] cf 70 [2] e1 52 [2] f5 49 [2] fa 53 [2] e4 4e [2] e6 4f [2] fd 49 [2] e1 4e [2] fd 61 }

  condition:
    any of them
}