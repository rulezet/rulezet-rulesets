rule TTP_XOR_QUAD_CurrentVersionRun_3afc {
  strings:
    $key_3afc = { 69 93 [2] 4d 9d [2] 66 b1 [2] 48 93 [2] 5c 88 [2] 53 92 [2] 4d 8f [2] 4f 8e [2] 54 88 [2] 48 8f [2] 54 a0 }

  condition:
    any of them
}