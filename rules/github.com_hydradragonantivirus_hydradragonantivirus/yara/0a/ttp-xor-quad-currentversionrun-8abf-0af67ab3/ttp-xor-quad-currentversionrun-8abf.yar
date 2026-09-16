rule TTP_XOR_QUAD_CurrentVersionRun_8abf {
  strings:
    $key_8abf = { d9 d0 [2] fd de [2] d6 f2 [2] f8 d0 [2] ec cb [2] e3 d1 [2] fd cc [2] ff cd [2] e4 cb [2] f8 cc [2] e4 e3 }

  condition:
    any of them
}