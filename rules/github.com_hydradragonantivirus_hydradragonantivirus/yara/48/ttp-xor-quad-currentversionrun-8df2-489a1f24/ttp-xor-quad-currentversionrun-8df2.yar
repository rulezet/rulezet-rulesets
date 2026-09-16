rule TTP_XOR_QUAD_CurrentVersionRun_8df2 {
  strings:
    $key_8df2 = { de 9d [2] fa 93 [2] d1 bf [2] ff 9d [2] eb 86 [2] e4 9c [2] fa 81 [2] f8 80 [2] e3 86 [2] ff 81 [2] e3 ae }

  condition:
    any of them
}