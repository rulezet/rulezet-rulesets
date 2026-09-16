rule TTP_XOR_QUAD_CurrentVersionRun_3aef {
  strings:
    $key_3aef = { 69 80 [2] 4d 8e [2] 66 a2 [2] 48 80 [2] 5c 9b [2] 53 81 [2] 4d 9c [2] 4f 9d [2] 54 9b [2] 48 9c [2] 54 b3 }

  condition:
    any of them
}