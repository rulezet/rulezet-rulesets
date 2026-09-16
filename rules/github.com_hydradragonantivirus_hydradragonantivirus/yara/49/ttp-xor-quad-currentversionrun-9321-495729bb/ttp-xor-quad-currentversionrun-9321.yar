rule TTP_XOR_QUAD_CurrentVersionRun_9321 {
  strings:
    $key_9321 = { c0 4e [2] e4 40 [2] cf 6c [2] e1 4e [2] f5 55 [2] fa 4f [2] e4 52 [2] e6 53 [2] fd 55 [2] e1 52 [2] fd 7d }

  condition:
    any of them
}