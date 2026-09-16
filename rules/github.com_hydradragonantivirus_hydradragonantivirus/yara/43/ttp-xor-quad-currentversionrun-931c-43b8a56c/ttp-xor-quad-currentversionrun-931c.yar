rule TTP_XOR_QUAD_CurrentVersionRun_931c {
  strings:
    $key_931c = { c0 73 [2] e4 7d [2] cf 51 [2] e1 73 [2] f5 68 [2] fa 72 [2] e4 6f [2] e6 6e [2] fd 68 [2] e1 6f [2] fd 40 }

  condition:
    any of them
}