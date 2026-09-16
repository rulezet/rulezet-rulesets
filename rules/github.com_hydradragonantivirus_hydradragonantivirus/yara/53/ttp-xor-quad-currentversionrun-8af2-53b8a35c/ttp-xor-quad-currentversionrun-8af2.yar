rule TTP_XOR_QUAD_CurrentVersionRun_8af2 {
  strings:
    $key_8af2 = { d9 9d [2] fd 93 [2] d6 bf [2] f8 9d [2] ec 86 [2] e3 9c [2] fd 81 [2] ff 80 [2] e4 86 [2] f8 81 [2] e4 ae }

  condition:
    any of them
}