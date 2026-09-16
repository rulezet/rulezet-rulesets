rule TTP_XOR_QUAD_CurrentVersionRun_936d {
  strings:
    $key_936d = { c0 02 [2] e4 0c [2] cf 20 [2] e1 02 [2] f5 19 [2] fa 03 [2] e4 1e [2] e6 1f [2] fd 19 [2] e1 1e [2] fd 31 }

  condition:
    any of them
}