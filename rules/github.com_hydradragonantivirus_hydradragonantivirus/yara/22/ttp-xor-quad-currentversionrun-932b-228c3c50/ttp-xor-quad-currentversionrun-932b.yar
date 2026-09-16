rule TTP_XOR_QUAD_CurrentVersionRun_932b {
  strings:
    $key_932b = { c0 44 [2] e4 4a [2] cf 66 [2] e1 44 [2] f5 5f [2] fa 45 [2] e4 58 [2] e6 59 [2] fd 5f [2] e1 58 [2] fd 77 }

  condition:
    any of them
}