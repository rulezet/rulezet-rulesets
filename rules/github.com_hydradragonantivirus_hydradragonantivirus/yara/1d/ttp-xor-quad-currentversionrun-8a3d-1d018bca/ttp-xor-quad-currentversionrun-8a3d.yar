rule TTP_XOR_QUAD_CurrentVersionRun_8a3d {
  strings:
    $key_8a3d = { d9 52 [2] fd 5c [2] d6 70 [2] f8 52 [2] ec 49 [2] e3 53 [2] fd 4e [2] ff 4f [2] e4 49 [2] f8 4e [2] e4 61 }

  condition:
    any of them
}