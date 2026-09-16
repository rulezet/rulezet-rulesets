rule TTP_XOR_QUAD_CurrentVersionRun_932c {
  strings:
    $key_932c = { c0 43 [2] e4 4d [2] cf 61 [2] e1 43 [2] f5 58 [2] fa 42 [2] e4 5f [2] e6 5e [2] fd 58 [2] e1 5f [2] fd 70 }

  condition:
    any of them
}