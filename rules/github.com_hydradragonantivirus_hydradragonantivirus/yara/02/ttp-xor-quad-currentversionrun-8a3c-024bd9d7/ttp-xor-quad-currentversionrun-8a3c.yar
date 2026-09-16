rule TTP_XOR_QUAD_CurrentVersionRun_8a3c {
  strings:
    $key_8a3c = { d9 53 [2] fd 5d [2] d6 71 [2] f8 53 [2] ec 48 [2] e3 52 [2] fd 4f [2] ff 4e [2] e4 48 [2] f8 4f [2] e4 60 }

  condition:
    any of them
}