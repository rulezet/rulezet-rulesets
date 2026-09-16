rule TTP_XOR_QUAD_CurrentVersionRun_8d80 {
  strings:
    $key_8d80 = { de ef [2] fa e1 [2] d1 cd [2] ff ef [2] eb f4 [2] e4 ee [2] fa f3 [2] f8 f2 [2] e3 f4 [2] ff f3 [2] e3 dc }

  condition:
    any of them
}