rule TTP_XOR_QUAD_CurrentVersionRun_8d10 {
  strings:
    $key_8d10 = { de 7f [2] fa 71 [2] d1 5d [2] ff 7f [2] eb 64 [2] e4 7e [2] fa 63 [2] f8 62 [2] e3 64 [2] ff 63 [2] e3 4c }

  condition:
    any of them
}