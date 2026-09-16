rule TTP_XOR_QUAD_CurrentVersionRun_8a15 {
  strings:
    $key_8a15 = { d9 7a [2] fd 74 [2] d6 58 [2] f8 7a [2] ec 61 [2] e3 7b [2] fd 66 [2] ff 67 [2] e4 61 [2] f8 66 [2] e4 49 }

  condition:
    any of them
}